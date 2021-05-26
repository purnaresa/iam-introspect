package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sns"
)

var (
	svcIam   *iam.IAM
	svcSns   *sns.SNS
	topicSns string
	region   string
)

func init() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Initialize IAM Introspect")
	region = os.Getenv("INTROSPECT_REGION")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		log.Fatalln("Error while creating session,", err)
		return
	}

	svcIam = iam.New(sess)
	svcSns = sns.New(sess)
	topicSns = os.Getenv("INTROSPECT_SNS_TOPIC")
}

func main() {
	lambda.Start(CheckSAML)
}

func CheckSAML(ctx context.Context) (err error) {
	log.Println("Call IAM ListSAMLProviders")
	input := iam.ListSAMLProvidersInput{}
	output, err := svcIam.ListSAMLProviders(&input)
	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, provider := range output.SAMLProviderList {
		errDelete := DeleteSAML(provider)
		if errDelete != nil {
			err = errDelete
			log.Println(err.Error())
			return
		}
		errEmail := SendEmail(*provider.Arn)
		if errEmail != nil {
			err = errEmail
			log.Println(err.Error())
			return
		}
	}
	return
}

func SendEmail(samlArn string) (err error) {
	log.Println("Call SNS Publish")
	content := fmt.Sprintf(`
	Identity providers creation detected!.
	Following Identity Provider is deleted : 
	%+v

	To Do:
	1. Notify Security Team
	2. Check any IAM User and IAM Role in the account
		`, samlArn)
	input := sns.PublishInput{
		TopicArn: aws.String(topicSns),
		Subject:  aws.String("Warning - Identity providers created"),
		Message:  aws.String(content),
	}
	_, err = svcSns.Publish(&input)
	if err != nil {
		log.Println(err.Error())
	}
	return
}

func DeleteSAML(saml *iam.SAMLProviderListEntry) (err error) {
	input := iam.DeleteSAMLProviderInput{
		SAMLProviderArn: saml.Arn,
	}
	_, err = svcIam.DeleteSAMLProvider(&input)
	if err != nil {
		log.Println(err.Error())
		return
	}
	return
}
