package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/ssm"
)

var (
	svcIam       *iam.IAM
	svcSsm       *ssm.SSM
	keyThreshold int
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Initialize IAM Introspect")
	keyThresholdString := os.Getenv("ROTATE_KEY_THRESHOLD")
	keyThreshold, _ = strconv.Atoi(keyThresholdString)
	region := os.Getenv("ROTATE_KEY_REGION")
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String(region),
		},
		SharedConfigState: session.SharedConfigEnable,
	})

	if err != nil {
		log.Fatalln("Error while creating session,", err)
	}

	svcIam = iam.New(sess)
	svcSsm = ssm.New(sess)
}

func main() {
	isLambda := len(os.Getenv("_LAMBDA_SERVER_PORT")) > 0
	if isLambda == true {
		lambda.Start(rotateKey)
	} else {
		rotateKey()
	}

}

func rotateKey() {
	users := getIamUser()

	for _, user := range users {
		generateNewKey(user)

	}

}

type IamUser struct {
	User            string `json:"user"`
	AccessKeyStored string `json:"access_key"`
	SecretKeyStored string `json:"secret_key"`
	AccessKeyNew    string
	SecretKeyNew    string
	ParameterStore  string
}

func (i *IamUser) CheckThreshold() (over bool, err error) {
	inputList := iam.ListAccessKeysInput{
		UserName: &i.User,
	}

	accessKeys, err := svcIam.ListAccessKeys(&inputList)
	if err != nil {
		log.Println(err)
		return
	}

	if len(accessKeys.AccessKeyMetadata) == 1 {
		over := accessKeys.AccessKeyMetadata[0].CreateDate.
			Add(1 * time.Minute).
			After(time.Now())
		if over == true {
			// create new key
			outputCreateKey, errCreateKey := svcIam.CreateAccessKey(&iam.CreateAccessKeyInput{
				UserName: &i.User,
			})
			if errCreateKey != nil {
				log.Println(errCreateKey)
				// return
			}
			log.Println(outputCreateKey)
			// update parameter store
		}
	} else if len(accessKeys.AccessKeyMetadata) > 1 {
		// find older key
		oldKey := iam.AccessKeyMetadata{}
		newKey := iam.AccessKeyMetadata{}

		if accessKeys.AccessKeyMetadata[0].CreateDate.After(*accessKeys.AccessKeyMetadata[1].CreateDate) == true {
			oldKey = *accessKeys.AccessKeyMetadata[0]
			newKey = *accessKeys.AccessKeyMetadata[1]

		} else {
			oldKey = *accessKeys.AccessKeyMetadata[1]
			newKey = *accessKeys.AccessKeyMetadata[0]
		}

		// check new key pass threshold
		timeThreshold := time.Now().
			Add(time.Minute * time.Duration(keyThreshold))

		if newKey.CreateDate.After(timeThreshold) == true {
			_, errDeleteKey := svcIam.DeleteAccessKey(&iam.DeleteAccessKeyInput{
				AccessKeyId: oldKey.AccessKeyId,
			})
			if errDeleteKey != nil {
				log.Println(errDeleteKey)
				return
			}

		}

		// create new key
		outputCreateKey, errCreateKey := svcIam.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: &i.User,
		})
		if errCreateKey != nil {
			log.Println(errCreateKey)
			return
		}
		log.Println(outputCreateKey)

		// update parameter store
	}

	return
}

func getIamUser() (users []IamUser) {
	log.Println("get IAM User")
	appList := os.Getenv("ROTATE_KEY_APP_LIST")
	apps := strings.Split(appList, ",")
	for _, v := range apps {
		// read from parameter store
		i := ssm.GetParameterInput{
			Name:           aws.String(v),
			WithDecryption: aws.Bool(true),
		}

		o, err := svcSsm.GetParameter(&i)
		if err != nil {
			log.Println(err)
			continue
		}
		u := IamUser{}

		errParse := json.Unmarshal([]byte(*o.Parameter.Value), &u)
		if errParse != nil {
			log.Println(errParse)
			continue
		}
		u.ParameterStore = v
		users = append(users, u)
		//
	}
	return
}

func generateNewKey(user IamUser) {
	log.Printf("generate key for %s\n", user.User)
	thresholdOver, _ := user.CheckThreshold()
	if thresholdOver == false {
		return
	}

	// create new access key

	// update parameter store

	// deactive old access key
}
