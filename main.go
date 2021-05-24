package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sns"
)

var (
	svcIam   *iam.IAM
	svcSns   *sns.SNS
	topicSns string
)

func init() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Initialize IAM Introspect")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ap-southeast-1"),
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
	CheckSAML()
}

func CheckSAML() {
	log.Println("Call IAM ListSAMLProviders")
	input := iam.ListSAMLProvidersInput{}
	output, err := svcIam.ListSAMLProviders(&input)
	if err != nil {
		log.Fatalln(err.Error())
	}
	count := len(output.SAMLProviderList)
	log.Printf("Provider Count: %d", count)
	if count > 0 {
		SendEmail(*output)
	}
}

func SendEmail(saml iam.ListSAMLProvidersOutput) {
	log.Println("Call SNS Publish")
	content := fmt.Sprintf(`
	Identity providers creation detected!.
	Identity Providers List : %+v

	To Do:
	1. Notify Security Team
	2. Remove Identity providers via AWS Console - IAM
	`, saml.SAMLProviderList)
	input := sns.PublishInput{
		TopicArn: aws.String(topicSns),
		Subject:  aws.String("Warning - Identity providers created"),
		// MessageStructure: aws.String("json"),
		Message: aws.String(content),
	}
	_, err := svcSns.Publish(&input)
	if err != nil {
		log.Fatalln(err.Error())
	}

}
