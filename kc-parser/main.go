package main

import (
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocql/gocql"
	"github.com/joho/godotenv"
	amqp "github.com/rabbitmq/amqp091-go"
)

type Config struct {
	RabbitURL         string
	RabbitQueue       string
	CassandraHost     string
	CassandraKeyspace string
	MailTimeout       int
}

type Mail struct {
	MID        string
	ICID       string
	Sender     string
	Recipients map[string]bool
	Subject    string
	MessageID  string
	RawLogs    []string
	Created    time.Time
}

type InjectionConnection struct {
	ICID    string
	Created time.Time
	Logs    []string
}

type DeliveryConnection struct {
	DCID    string
	Created time.Time
	Logs    []string
}

var (
	mails   = make(map[string]*Mail)
	icids   = make(map[string]*InjectionConnection)
	dcids   = make(map[string]*DeliveryConnection)
	lock    sync.Mutex
	session *gocql.Session
)

var (
	midRegex            = regexp.MustCompile(`MID\s+(\d+)`)
	icidRegex           = regexp.MustCompile(`ICID\s+(\d+)`)
	dcidRegex           = regexp.MustCompile(`DCID\s+(\d+)`)
	fromRegex           = regexp.MustCompile(`From:\s*<([^>]+)>`)
	SDRReverseDNSRegex  = regexp.MustCompile(`SDR:\s+reverse\s+DNS\s+host:\s+'([^>]+)`)
	SDRScanResultRegex  = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	sizeRegex           = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	policyMatchedRegex  = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	grayMailRegex       = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	caseSpamRegex       = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	mcafeeAVRegex       = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	sophosAVRegex       = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	antivirusRegex      = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	ampRegex            = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	toRegex             = regexp.MustCompile(`To:\s*<([^>]+)>`)
	messageIDRegex      = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	subjectRegex        = regexp.MustCompile(`Subject\s+\"([^\"]+)\"`)
	antiSpamRegex       = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	statusRegex         = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
	outbreakFilterRegex = regexp.MustCompile(`Message-ID\s+'<([^>]+)>`)
)

func loadConfig() Config {
	_ = godotenv.Load(".env")
	mailTimeout, _ := strconv.Atoi(os.Getenv("MAIL_TIMEOUT_SECONDS"))
	return Config{
		RabbitURL:         os.Getenv("RABBITMQ_URL"),
		RabbitQueue:       os.Getenv("RABBITMQ_QUEUE"),
		CassandraHost:     os.Getenv("CASSANDRA_HOST"),
		CassandraKeyspace: os.Getenv("CASSANDRA_KEYSPACE"),
		MailTimeout:       mailTimeout,
	}
}

func connectCassandra(config Config) {
	cluster := gocql.NewCluster(config.CassandraHost)
	cluster.Keyspace = config.CassandraKeyspace
	cluster.Consistency = gocql.Quorum
	var err error
	session, err = cluster.CreateSession()
	failOnError(err, "Failed to connect to Cassandra")
}

func insertMail(mail *Mail) {
	if len(mail.Recipients) == 0 {
		return
	}
	var recipient string
	for r := range mail.Recipients {
		recipient = r
		break
	}
	id := gocql.TimeUUID()
	err := session.Query(`
        INSERT INTO mail_logs (id, log_time, message_id, sender, recipient, subject, mid, icid, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		time.Now(),
		mail.MessageID,
		mail.Sender,
		recipient,
		mail.Subject,
		mail.MID,
		mail.ICID,
		strings.Join(mail.RawLogs, "\n"),
	).Exec()
	if err != nil {
		log.Printf("❌ Cassandra insert error: %v", err)
	} else {
		log.Printf("✅ Mail saved: MID=%s", mail.MID)
	}
}

func processLog(logLine string, mailTimeout int) {
	logLine = strings.TrimSpace(logLine)
	lock.Lock()
	defer lock.Unlock()

	if midMatch := midRegex.FindStringSubmatch(logLine); midMatch != nil {
		mid := midMatch[1]
		mail, exists := mails[mid]
		if !exists {
			mail = &Mail{
				MID:        mid,
				Recipients: map[string]bool{},
				Created:    time.Now(),
			}
			mails[mid] = mail
		}
		mail.RawLogs = append(mail.RawLogs, logLine)
		if icid := icidRegex.FindStringSubmatch(logLine); icid != nil {
			mail.ICID = icid[1]
		}
		if from := fromRegex.FindStringSubmatch(logLine); from != nil {
			mail.Sender = from[1]
		}
		if to := toRegex.FindStringSubmatch(logLine); to != nil {
			mail.Recipients[to[1]] = true
		}
		if subject := subjectRegex.FindStringSubmatch(logLine); subject != nil {
			mail.Subject = subject[1]
		}
		if msgid := messageIDRegex.FindStringSubmatch(logLine); msgid != nil {
			mail.MessageID = msgid[1]
		}
		if mail.Sender != "" && mail.Subject != "" && mail.MessageID != "" && len(mail.Recipients) > 0 {
			insertMail(mail)
			delete(mails, mid)
		}
	}

	if dcid := dcidRegex.FindStringSubmatch(logLine); dcid != nil {
		obj, ok := dcids[dcid[1]]
		if !ok {
			obj = &DeliveryConnection{DCID: dcid[1], Created: time.Now()}
			dcids[dcid[1]] = obj
		}
		obj.Logs = append(obj.Logs, logLine)
	}

	if icid := icidRegex.FindStringSubmatch(logLine); icid != nil {
		obj, ok := icids[icid[1]]
		if !ok {
			obj = &InjectionConnection{ICID: icid[1], Created: time.Now()}
			icids[icid[1]] = obj
		}
		obj.Logs = append(obj.Logs, logLine)
	}
}

func cleanupLoop(timeout int) {
	for {
		time.Sleep(10 * time.Second)
		now := time.Now()
		lock.Lock()
		for mid, mail := range mails {
			if now.Sub(mail.Created) > time.Duration(timeout)*time.Second {
				log.Printf("⚠️ Mail timeout. Discarding MID=%s", mid)
				delete(mails, mid)
			}
		}
		for id, obj := range icids {
			if now.Sub(obj.Created) > time.Duration(timeout)*time.Second {
				log.Printf("⚠️ ICID timeout. Discarding ICID=%s", id)
				delete(icids, id)
			}
		}
		for id, obj := range dcids {
			if now.Sub(obj.Created) > time.Duration(timeout)*time.Second {
				log.Printf("⚠️ DCID timeout. Discarding DCID=%s", id)
				delete(dcids, id)
			}
		}
		lock.Unlock()
	}
}

func consumeRabbitMQ(config Config) {
	conn, err := amqp.Dial(config.RabbitURL)
	failOnError(err, "Failed to connect to RabbitMQ")
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	q, err := ch.QueueDeclare(config.RabbitQueue, true, false, false, false, nil)
	failOnError(err, "Failed to declare a queue")
	msgs, err := ch.Consume(q.Name, "", true, false, false, false, nil)
	failOnError(err, "Failed to register a consumer")
	for d := range msgs {
		go processLog(string(d.Body), config.MailTimeout)
	}
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	config := loadConfig()
	connectCassandra(config)
	go cleanupLoop(config.MailTimeout)
	consumeRabbitMQ(config)
}
