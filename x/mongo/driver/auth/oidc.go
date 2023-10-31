package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func newOIDCAuthenticator(cred *Cred) (Authenticator, error) {
	return &OIDCAuthenticator{
		AuthMechanismProperties: cred.Props,
	}, nil
}

// OIDCAuthenticator uses the PLAIN algorithm over SASL to authenticate a connection.
type OIDCAuthenticator struct {
	AuthMechanismProperties map[string]string
}

// Auth authenticates the connection.
func (a *OIDCAuthenticator) Auth(ctx context.Context, cfg *Config) error {
	// TODO: cache.Get()
	token, err := cfg.OIDCCallback(ctx, &OIDCArgs{})
	if err != nil {
		return err
	}
	// TODO: cache.Set(token)
	return ConductSaslConversation(ctx, cfg, "$external", &oidcSASLClient{jwt: token.AccessToken})
}

type oidcSASLClient struct {
	jwt string
}

var _ SaslClient = (*oidcSASLClient)(nil)

func (c *oidcSASLClient) Start() (string, []byte, error) {
	b, err := bson.Marshal(bson.M{"jwt": c.jwt})
	if err != nil {
		return "", nil, err
	}
	return "MONGODB-OIDC", b, nil
}

func (c *oidcSASLClient) Next([]byte) ([]byte, error) {
	return nil, newAuthError("unexpected step in OIDC automatic authentication", nil)
}

func (c *oidcSASLClient) Completed() bool {
	return true
}

// ======= Callbacks ========== //

type OIDCArgs struct{}

type OIDCToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

type OIDCCallback func(context.Context, *OIDCArgs) (*OIDCToken, error)

func AWSCallback() OIDCCallback {
	return func(context.Context, *OIDCArgs) (*OIDCToken, error) {
		token, err := os.ReadFile(os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
		if err != nil {
			return nil, err
		}
		return &OIDCToken{
			AccessToken: string(token),
		}, nil
	}
}

// audience = authMechanismProperties["TOKEN_AUDIENCE"]
func AzureCallback(audience string) OIDCCallback {
	return func(ctx context.Context, o *OIDCArgs) (*OIDCToken, error) {
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

		return &OIDCToken{
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
