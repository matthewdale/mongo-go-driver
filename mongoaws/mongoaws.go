package mongoaws

import (
	"context"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

func NewSigner(ctx context.Context) (*Signer, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &Signer{
		cfg: cfg,
	}, nil
}

func NewSignerWithConfig(cfg aws.Config) *Signer {
	return &Signer{
		cfg: cfg,
	}
}

type Signer struct {
	cfg  aws.Config
	cred *aws.Credentials
}

func (s *Signer) SignHTTP(ctx context.Context, req *http.Request, body, service, region string, signTime time.Time) error {
	cred, err := s.credentials()
	if err != nil {
		return err
	}

	sig := v4.NewSigner()
	return sig.SignHTTP(ctx, cred, req, hash(body), service, region, signTime)
}

func (s *Signer) SessionToken(ctx context.Context) (string, error) {
	cred, err := s.credentials()
	if err != nil {
		return "", err
	}
	return cred.SessionToken, nil
}

func (s *Signer) credentials() (aws.Credentials, error) {
	if s.cred != nil {
		return *s.cred, nil
	}

	cred, err := s.cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return aws.Credentials{}, err
	}

	s.cred = &cred
	return cred, nil
}

// TODO: Implement
func hash(string) string {
	return ""
}
