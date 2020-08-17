package client

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"strings"

	//"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v3"
)

// APIInterface is the basic interface for AD API
//type APIInterface interface {
//	connect() error
//	getDomainDN() string

// generic objects
//searchObject(filter, baseDN string, attributes []string) ([]*ADObject, error)
//getObject(dn string, attributes []string) (*ADObject, error)
//createObject(dn string, class []string, attributes map[string][]string) error
//deleteObject(dn string) error
//updateObject(dn string, classes []string, added, changed, removed map[string][]string) error

// computer objects
//getComputer(name string) (*Computer, error)
//createComputer(cn, ou, description string) error
//updateComputerOU(cn, ou, newOU string) error
//updateComputerDescription(cn, ou, description string) error
//deleteComputer(cn, ou string) error

// ou objects
//getOU(name, baseOU string) (*ADOU, error)
//createOU(name, baseOU, description string) error
//moveOU(cn, baseOU, newOU string) error
//updateOUName(name, baseOU, newName string) error
//updateOUDescription(cn, baseOU, description string) error
//deleteOU(dn string) error

// user objects
//getUser(name, baseOU string) (*ADUser, error)
//createUser(user CreateUser) error
//createUser(user ADUserRequest) error
//moveUser(cn, baseOU, newOU string) error
//updateUserName(name, baseOU, newName string) error
//updateUserDescription(cn, baseOU, description string) error
//deleteUser(dn string) error
//addUserToGroup(userdn, groupdn string)

//AD group Struct

//}

// API is the basic struct which should implement the interface
type Client struct {
	client   *Conn
	ADUser   ADUserService
	ADGroup  ADGroupService
	ADOU     ADOUService
	ADObject ADObjectService
}

type Conn struct {
	host     string
	port     int
	domain   string
	useTLS   bool
	insecure bool
	user     string
	password string
	conn     ldap.Conn
}

// connects to an Active Directory server

func (c *Client) connect() (*ldap.Conn, error) {
	log.Infof("Connecting to %s:%d.", c.client.host, c.client.port)

	if c.client.host == "" {
		return nil, fmt.Errorf("connect - no ad host specified")
	}

	if c.client.domain == "" {
		return nil, fmt.Errorf("connect - no ad domain specified")
	}

	if c.client.user == "" {
		return nil, fmt.Errorf("connect - no bind user specified")
	}

	client, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.client.host, c.client.port))
	if err != nil {
		return nil, fmt.Errorf("connect - failed to connect: %s", err)
	}

	log.Infof("Checking if tls connection is enabled %s", c.client.useTLS)

	//Note - Please provide the fqdn here ..
	ldapConfig := &tls.Config{InsecureSkipVerify: true, ServerName: c.client.host}
	log.Info("Configuring client to use secure connection.")
	client, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.client.host, 636), ldapConfig)
	if err != nil {
		return nil, fmt.Errorf("connect - failed to use secure connection: %s", err)
	}

	user := c.client.user
	if ok, e := regexp.MatchString(`.*,ou=.*`, c.client.user); e != nil || !ok {
		user = fmt.Sprintf("%s@%s", c.client.user, c.client.domain)
	}

	log.Infof("Authenticating user %s.", user)
	if err = client.Bind(user, c.client.password); err != nil {
		client.Close()
		return nil, fmt.Errorf("connect - authentication failed: %s", err)
	}

	log.Infof("Connected successfully to %s:%d.", c.client.host, c.client.port)
	return client, err
}

func (c *Client) getDomainDN() string {
	tmp := strings.Split(c.client.domain, ".")
	return strings.ToLower(fmt.Sprintf("dc=%s", strings.Join(tmp, ",dc=")))
}
