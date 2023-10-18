package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
)

var _ SpeculativeAuthenticator = (*OIDCAuthenticator)(nil)

const oidcMech = "MONGODB-OIDC"

func newOIDCAuthenticator(cred *Cred) (Authenticator, error) {
	oa := &OIDCAuthenticator{
		AuthMechanismProperties: cred.Props,
	}
	oa.accessToken.Store("")
	oa.refreshToken.Store("")
	return oa, nil
}

// OIDCAuthenticator uses ...
type OIDCAuthenticator struct {
	AuthMechanismProperties map[string]string

	mu sync.Mutex // Guards calling the callback.

	accessToken  atomic.Value // string
	idpInfo      atomic.Value // *IDPInfo
	refreshToken atomic.Value // string
}

func (oa *OIDCAuthenticator) providerCallback() (OIDCCallback, error) {
	provider, ok := oa.AuthMechanismProperties["PROVIDER_NAME"]
	if !ok {
		return nil, nil
	}

	switch provider {
	case "aws":
		return AWSCallback(), nil
	}

	return nil, fmt.Errorf("PROVIDER_NAME %q not supported for MONGODB-OIDC", provider)
}

func (oa *OIDCAuthenticator) getAccessToken(
	ctx context.Context,
	args *OIDCArgs,
	callback OIDCCallback,
) (string, error) {
	oa.mu.Lock()
	defer oa.mu.Unlock()

	accessToken := oa.accessToken.Load().(string)
	if accessToken != "" {
		return accessToken, nil
	}

	cred, err := callback(ctx, args)
	if err != nil {
		return "", err
	}

	// TODO: Do we need to check for empty here?
	if cred.AccessToken != "" {
		oa.accessToken.Store(cred.AccessToken)
	}
	return cred.AccessToken, nil
}

func (oa *OIDCAuthenticator) getAccessTokenWithRefresh(
	ctx context.Context,
	callback OIDCHumanCallback,
	refreshToken string,
) (string, error) {
	oa.mu.Lock()
	defer oa.mu.Unlock()

	idpInfo := oa.idpInfo.Load().(*IDPInfo)
	cred, err := callback(ctx, &OIDCHumanArgs{
		Version:      1,
		IDPInfo:      idpInfo,
		RefreshToken: refreshToken,
	})
	if err != nil {
		return "", err
	}

	oa.accessToken.Store(cred.AccessToken)
	return cred.AccessToken, nil
}

func (oa *OIDCAuthenticator) invalidateAccessToken(token string) {
	oa.accessToken.CompareAndSwap(token, "")
}

// Auth authenticates the connection.
func (oa *OIDCAuthenticator) Auth(ctx context.Context, cfg *Config) error {
	// TODO: Validate config is not ambiguous.

	accessToken := oa.accessToken.Load().(string)
	if accessToken != "" {
		err := ConductSaslConversation(ctx, cfg, "$external", &oidcOneStep{
			accessToken: accessToken,
		})
		if err == nil {
			return nil
		}
		// TODO: Check error type and raise if it's not a server-side error.
		oa.invalidateAccessToken(accessToken)
		time.Sleep(100 * time.Millisecond)
	}

	// cfg.OIDCHumanCallback = func(ctx context.Context, args *OIDCHumanArgs) (*OIDCHumanCredential, error) {
	// 	if args.IDPInfo == nil {
	// 		return nil, errors.New("IDPInfo required")
	// 	}
	// 	if args.RefreshToken != "" {
	// 		// Attempt to fetch an access token with a refresh token.
	// 	}

	// 	fmt.Println("CALLBACK IDPINFO", args.IDPInfo)
	// 	return &OIDCHumanCredential{
	// 		AccessToken: "",
	// 	}, nil
	// }

	if cfg.OIDCCallback != nil {
		accessToken, err := oa.getAccessToken(ctx, nil, cfg.OIDCCallback)
		if err != nil {
			return err
		}

		err = ConductSaslConversation(ctx, cfg, "$external", &oidcOneStep{
			accessToken: accessToken,
		})
		if err == nil {
			return nil
		}
		// TODO: Check error type and raise if it's not a server-side error.
		// Clear the access token if authentication failed.
		oa.invalidateAccessToken(accessToken)

		time.Sleep(100 * time.Millisecond)
		accessToken, err = oa.getAccessToken(ctx, &OIDCArgs{Version: 1}, cfg.OIDCCallback)
		if err != nil {
			return err
		}
		return ConductSaslConversation(ctx, cfg, "$external", &oidcOneStep{
			accessToken: accessToken,
		})
	}

	if callback := cfg.OIDCHumanCallback; callback != nil {
		// Cached access token auth.
		accessToken := oa.accessToken.Load().(string)
		if accessToken != "" {
			err := ConductSaslConversation(ctx, cfg, "$external", &oidcOneStep{
				accessToken: accessToken,
			})
			if err == nil {
				return nil
			}
			// Clear the access token if authentication failed.
			oa.invalidateAccessToken(accessToken)
		}

		// Refresh token auth.
		refreshToken := oa.refreshToken.Load().(string)
		if refreshToken != "" {
			accessToken, err := oa.getAccessTokenWithRefresh(ctx, callback, refreshToken)
			if err == nil {
				return nil
			}
			err = ConductSaslConversation(ctx, cfg, "$external", &oidcOneStep{
				accessToken: accessToken,
			})
			if err == nil {
				return nil
			}
			// Clear the access token if authentication failed.
			oa.invalidateAccessToken(accessToken)
		}

		// Two-step IDPInfo auth.
		return ConductSaslConversation(ctx, cfg, "$external", &oidcTwoStep{
			userPrincipal: "blah",
			credentialFn:  callback,
		})
	}

	callback, err := oa.providerCallback()
	if err != nil {
		return fmt.Errorf("error getting build-in OIDC provider: %w", err)
	}

	accessToken, err = oa.getAccessToken(ctx, &OIDCArgs{Version: 1}, callback)
	if err != nil {
		return fmt.Errorf("error getting access token from built-in OIDC provider: %w", err)
	}

	err = ConductSaslConversation(ctx, cfg, "$external", &oidcOneStep{
		accessToken: accessToken,
	})
	if err == nil {
		return nil
	}
	// TODO: Check error type and raise if it's not a server-side error.
	oa.invalidateAccessToken(accessToken)

	return err
}

// CreateSpeculativeConversation creates a speculative conversation for SCRAM authentication.
func (oa *OIDCAuthenticator) CreateSpeculativeConversation() (SpeculativeConversation, error) {
	accessToken := oa.accessToken.Load().(string)
	if accessToken == "" {
		return nil, nil // Skip speculative auth.
	}

	return newSaslConversation(&oidcOneStep{accessToken: accessToken}, "$external", true), nil
}

var _ SaslClient = (*oidcOneStep)(nil)

type oidcOneStep struct {
	accessToken string
}

func (oos *oidcOneStep) Start() (string, []byte, error) {
	return oidcMech, jwtStepRequest(oos.accessToken), nil
}

func (oos *oidcOneStep) Next(context.Context, []byte) ([]byte, error) {
	return nil, newAuthError("unexpected step in OIDC machine authentication", nil)
}

func (*oidcOneStep) Completed() bool {
	return true
}

var _ SaslClient = (*oidcTwoStep)(nil)

type oidcTwoStep struct {
	userPrincipal string
	credentialFn  OIDCHumanCallback

	credential *OIDCHumanCredential
}

func (ots *oidcTwoStep) Start() (string, []byte, error) {
	return oidcMech, principalStepRequest(ots.userPrincipal), nil
}

func (ots *oidcTwoStep) Next(ctx context.Context, msg []byte) ([]byte, error) {
	{
		var d bson.D
		bson.Unmarshal(msg, &d)
		fmt.Println("D", d)
	}

	var res IDPInfo
	err := bson.Unmarshal(msg, &res)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling BSON document: %w", err)
	}

	cred, err := ots.credentialFn(ctx, &OIDCHumanArgs{
		Version: 1,
		IDPInfo: &res,
	})
	if err != nil {
		return nil, fmt.Errorf("error calling callback: %w", err)
	}
	ots.credential = cred

	return jwtStepRequest(cred.AccessToken), nil
}

func jwtStepRequest(accessToken string) []byte {
	return bsoncore.NewDocumentBuilder().
		AppendString("jwt", accessToken).
		Build()
}

func principalStepRequest(principal string) []byte {
	doc := bsoncore.NewDocumentBuilder()
	if principal != "" {
		doc.AppendString("n", principal)
	}
	return doc.Build()
}

func (ohsc *oidcTwoStep) Completed() bool {
	return true
}

// ======= Callbacks ========== //

// OIDCArgs ...
type OIDCArgs struct {
	Version      int
	RefreshToken string
}

// OIDCCredential ...
type OIDCCredential struct {
	AccessToken string
	ExpiresAt   time.Time
}

type OIDCCallback func(context.Context, *OIDCArgs) (*OIDCCredential, error)

// IDPInfo ...
type IDPInfo struct {
	Issuer        string   `bson:"issuer"`
	ClientID      string   `bson:"clientId"`
	RequestScopes []string `bson:"requestScopes"`
}

// OIDCArgs ...
type OIDCHumanArgs struct {
	Version      int
	IDPInfo      *IDPInfo
	RefreshToken string
}

// OIDCCredential ...
type OIDCHumanCredential struct {
	AccessToken  string
	ExpiresAt    time.Time
	RefreshToken string
}

type OIDCHumanCallback func(context.Context, *OIDCHumanArgs) (*OIDCHumanCredential, error)

func AWSCallback() OIDCCallback {
	return func(context.Context, *OIDCArgs) (*OIDCCredential, error) {
		f := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
		if f == "" {
			return nil, errors.New("AWS_WEB_IDENTITY_TOKEN_FILE must be set")
		}
		token, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		return &OIDCCredential{
			AccessToken: string(token),
		}, nil
	}
}

// audience = authMechanismProperties["TOKEN_AUDIENCE"]
func AzureCallback(audience string) OIDCCallback {
	return func(ctx context.Context, o *OIDCArgs) (*OIDCCredential, error) {
		// TODO: Static headers.
		res, err := http.Get("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + audience)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		var response struct {
			AccessToken string `json:"access_token"`
			ExpiresAt   string `json:"expires_at"`
		}
		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, err
		}

		expiresAt := time.Now().Add(12 * time.Hour) // TODO: Parse ExpiresAt

		return &OIDCCredential{
			AccessToken: response.AccessToken,
			ExpiresAt:   expiresAt,
		}, nil
	}
}

// client_id, client_secret, username, token_file, audience?
// get_provider: issuer, jwks_uri, rsa_key,

// def callback(client_info, server_info):

// def get_id_token(config=None, expires=None):
//     """Get a valid ID token."""
//     config = config or get_default_config()
//     provider = get_provider(config=config, expires=expires)
//     client_id = config['client_id']
//     client_secret = config['client_secret']
//     response = provider.parse_authentication_request(f'response_type=code&client_id={client_id}&scope=openid&redirect_uri={MOCK_ENDPOINT}')
//     resp = provider.authorize(response, config['username'])
//     code = resp.to_dict()["code"]
//     creds = f'{client_id}:{client_secret}'
//     creds = base64.urlsafe_b64encode(creds.encode('utf-8')).decode('utf-8')
//     headers = dict(Authorization=f'Basic {creds}')
//     extra_claims = {'foo': ['readWrite'], 'bar': ['read'] }
//     response = provider.handle_token_request(f'grant_type=authorization_code&subject_type=public&code={code}&redirect_uri={MOCK_ENDPOINT}', headers, extra_id_token_claims=extra_claims)

//     token = response["id_token"]
//     if config['token_file']:
//         with open(config['token_file'], 'w') as fid:
//             print(f"Writing token file: {config['token_file']}")
//             fid.write(token)
//     return token

// def main():
//     token_dir = os.environ['OIDC_TOKEN_DIR'].replace(os.sep, '/')
//     os.makedirs(token_dir, exist_ok=True)
//     secrets = get_secrets()
//     config = {
//         "issuer": secrets['oidc_issuer_1_uri'],
//         "jwks_uri": secrets['oidc_jwks_uri'],
//         'rsa_key': secrets['oidc_rsa_key'],
//         'audience': DEFAULT_CLIENT,
//         'client_id': DEFAULT_CLIENT,
//         'client_secret': secrets['oidc_client_secret'],
//         'username': 'test_user1',
//         'token_file': join(token_dir, 'test_user1')
//     }
//     get_id_token(config)
//     for i in range(2):
//         config['token_file'] = join(token_dir, f'test_user1_{i+1}')
//         get_id_token(config)
//     config['issuer'] = secrets['oidc_issuer_2_uri']
//     config['username'] = 'test_user2'
//     config['token_file'] = join(token_dir, 'test_user2')
//     get_id_token(config)
//     for i in range(2):
//         config['token_file'] = join(token_dir, f'test_user2_{i+1}')
//         get_id_token(config)
//     config['issuer'] = secrets['oidc_issuer_1_uri']
//     config['username'] = 'test_user1'
//     config['token_file'] = join(token_dir, 'test_user1_expires')
//     get_id_token(config, expires=60)

//     print(f"Wrote tokens to {token_dir}")

// if __name__ == '__main__':
//     main()
