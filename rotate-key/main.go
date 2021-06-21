package main

import (
	"encoding/json"
	// "log"

	// "log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/ssm"
	log "github.com/sirupsen/logrus"
)

var (
	svcIam       *iam.IAM
	svcSsm       *ssm.SSM
	keyThreshold int
	isLambda     bool
)

func init() {
	isLambda = len(os.Getenv("_LAMBDA_SERVER_PORT")) > 0
	if isLambda {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetReportCaller(true)
		log.SetLevel(log.DebugLevel)
	}
	log.Info("Initialize IAM Introspect")
	keyThresholdString := os.Getenv("ROTATE_KEY_THRESHOLD")
	keyThreshold, _ = strconv.Atoi(keyThresholdString)
	log.WithField("minute", keyThreshold).Info("Access key age threshold")
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
	if isLambda == true {
		log.Info("run in lambda")
		lambda.Start(rotateKey)
	} else {
		log.Info("run in non lambda")
		rotateKey()
	}

}

func rotateKey() {
	users := getIamUser()

	for _, user := range users {
		user.GenerateNewKey()
	}

}

type IamUser struct {
	User            string `json:"UserName"`
	AccessKeyStored string `json:"AccessKeyId"`
	SecretKeyStored string `json:"SecretAccessKey"`
	AccessKeyNew    string
	SecretKeyNew    string
	ParameterStore  string
}

func (i *IamUser) GenerateNewKey() {
	log.WithField("user", i.User).Debug("Generate New Key")
	inputList := iam.ListAccessKeysInput{
		UserName: &i.User,
	}

	accessKeys, err := svcIam.ListAccessKeys(&inputList)
	if err != nil {
		log.Warn(err)
		return
	}
	if len(accessKeys.AccessKeyMetadata) == 1 {
		log.Debug("Single access key detected")
		over := accessKeys.AccessKeyMetadata[0].CreateDate.
			Add(time.Duration(keyThreshold) * time.Minute).
			Before(time.Now().UTC())
		if over == true {
			// create new key
			outputCreateKey, errCreateKey := svcIam.CreateAccessKey(&iam.CreateAccessKeyInput{
				UserName: &i.User,
			})
			if errCreateKey != nil {
				log.Warn(errCreateKey)
				// return
			}
			log.Info(outputCreateKey)
			// update parameter store
		}
	} else if len(accessKeys.AccessKeyMetadata) > 1 {
		log.Debug("Multi access key detected")

		// find older key
		oldKey := iam.AccessKeyMetadata{}
		newKey := iam.AccessKeyMetadata{}
		if accessKeys.AccessKeyMetadata[0].CreateDate.After(*accessKeys.AccessKeyMetadata[1].CreateDate) == true {
			oldKey = *accessKeys.AccessKeyMetadata[1]
			newKey = *accessKeys.AccessKeyMetadata[0]
		} else {
			oldKey = *accessKeys.AccessKeyMetadata[0]
			newKey = *accessKeys.AccessKeyMetadata[1]
		}

		// check new key pass threshold
		over := newKey.CreateDate.
			Add(time.Duration(keyThreshold) * time.Minute).
			Before(time.Now().UTC())
		if over == false {
			log.Debug("No access key over threshold")
			return
		}
		log.Debug("Access key over threshold")
		log.WithField("access_key", *oldKey.AccessKeyId).Debug("Delete access key")
		_, errDeleteKey := svcIam.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			UserName:    &i.User,
			AccessKeyId: oldKey.AccessKeyId,
		})
		if errDeleteKey != nil {
			log.Warn(errDeleteKey)
			return
		}

		// create new key
		log.WithField("user", i.User).Debug("Create new access key")
		outputCreateKey, errCreateKey := svcIam.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: &i.User,
		})
		if errCreateKey != nil {
			log.Warn(errCreateKey)
			return
		}

		// update parameter store
		data, errMarshal := json.Marshal(outputCreateKey.AccessKey)
		if errMarshal != nil {
			log.Warn(errMarshal.Error())
			return
		}
		_, errPutParameter := svcSsm.PutParameter(&ssm.PutParameterInput{
			Name:      aws.String(i.ParameterStore),
			Value:     aws.String(string(data)),
			Overwrite: aws.Bool(true),
		})
		if errPutParameter != nil {
			log.Warn(errPutParameter.Error())
			return
		}

	}

	return
}

func getIamUser() (users []IamUser) {
	log.Debug("get IAM User")
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
			log.Warn(err)
			continue
		}
		u := IamUser{}

		errParse := json.Unmarshal([]byte(*o.Parameter.Value), &u)
		if errParse != nil {
			log.Warn(errParse)
			continue
		}
		u.ParameterStore = v
		users = append(users, u)
		//
	}
	return
}
