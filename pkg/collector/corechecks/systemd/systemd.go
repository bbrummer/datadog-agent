// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2019 Datadog, Inc.

package systemd

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/coreos/go-systemd/dbus"
	"gopkg.in/yaml.v2"

	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
)

const (
	systemdCheckName = "systemd"

	unitTag            = "unit"
	unitActiveStateTag = "active_state"
	unitSubStateTag    = "sub_state"

	unitActiveState = "active"

	unitTypeUnit    = "Unit"
	unitTypeService = "Service"

	serviceSuffix = "service"

	canConnectServiceCheckName = "systemd.can_connect"
)

// serviceUnitConfig is a config/mapping of services properties (a service is a unit of service type).
// Each config define a metric to be monitored, how it should be retrieved and processed.
type serviceUnitConfig struct {
	metricName         string
	propertyName       string
	accountingProperty string
	required           bool // if required log as error when there is an issue getting the property, otherwise log as debug
}

var serviceUnitConfigList = []serviceUnitConfig{
	{metricName: "systemd.unit.cpu_usage_n_sec", propertyName: "CPUUsageNSec", accountingProperty: "CPUAccounting", required: true},
	{metricName: "systemd.unit.memory_current", propertyName: "MemoryCurrent", accountingProperty: "MemoryAccounting", required: true},
	{metricName: "systemd.unit.tasks_current", propertyName: "TasksCurrent", accountingProperty: "TasksAccounting", required: true},
	{metricName: "systemd.unit.n_restarts", propertyName: "NRestarts", accountingProperty: "", required: false}, // only present from systemd v235
}

var unitActiveStateList = []struct {
	metricName  string
	activeState string
}{
	{"systemd.unit.active.count", "active"},
	{"systemd.unit.activating.count", "activating"},
	{"systemd.unit.inactive.count", "inactive"},
	{"systemd.unit.deactivating.count", "deactivating"},
	{"systemd.unit.failed.count", "failed"},
}

var systemdStatusMapping = map[string]metrics.ServiceCheckStatus{
	"initializing": metrics.ServiceCheckUnknown,
	"starting":     metrics.ServiceCheckUnknown,
	"running":      metrics.ServiceCheckOK,
	"degraded":     metrics.ServiceCheckWarning,
	"maintenance":  metrics.ServiceCheckUnknown,
	"stopping":     metrics.ServiceCheckUnknown,
}

// Check aggregates metrics from one Check instance
type Check struct {
	core.CheckBase
	stats  systemdStats
	config systemdConfig
}

type systemdInstanceConfig struct {
	UnitNames         []string `yaml:"unit_names"`
	UnitRegexStrings  []string `yaml:"unit_regex"`
	UnitRegexPatterns []*regexp.Regexp
}

type systemdInitConfig struct{}

type systemdConfig struct {
	instance systemdInstanceConfig
	initConf systemdInitConfig
}

type systemdStats interface {
	// Dbus Connection
	NewConn() (*dbus.Conn, error)
	CloseConn(c *dbus.Conn)

	// System Data
	SystemState(c *dbus.Conn) (*dbus.Property, error)
	ListUnits(c *dbus.Conn) ([]dbus.UnitStatus, error)
	GetUnitTypeProperties(c *dbus.Conn, unitName string, unitType string) (map[string]interface{}, error)

	// Misc
	TimeNanoNow() int64
}

type defaultSystemdStats struct{}

func (s *defaultSystemdStats) NewConn() (*dbus.Conn, error) {
	return dbus.New()
}

func (s *defaultSystemdStats) CloseConn(c *dbus.Conn) {
	c.Close()
}

func (s *defaultSystemdStats) SystemState(c *dbus.Conn) (*dbus.Property, error) {
	return c.SystemState()
}

func (s *defaultSystemdStats) ListUnits(conn *dbus.Conn) ([]dbus.UnitStatus, error) {
	return conn.ListUnits()
}

func (s *defaultSystemdStats) GetUnitTypeProperties(c *dbus.Conn, unitName string, unitType string) (map[string]interface{}, error) {
	return c.GetUnitTypeProperties(unitName, unitType)
}

func (s *defaultSystemdStats) TimeNanoNow() int64 {
	return time.Now().UnixNano()
}

// Run executes the check
func (c *Check) Run() error {
	sender, err := aggregator.GetSender(c.ID())
	if err != nil {
		return err
	}

	conn, err := c.getConn(sender)
	if err != nil {
		return err
	}
	defer c.stats.CloseConn(conn)

	err = c.submitUnitMetrics(sender, conn)
	if err != nil {
		return err
	}
	sender.Commit()
	return nil
}

func (c *Check) getConn(sender aggregator.Sender) (*dbus.Conn, error) {
	conn, err := c.stats.NewConn()
	if err != nil {
		newErr := fmt.Errorf("Cannot create a connection: %v", err)
		sender.ServiceCheck(canConnectServiceCheckName, metrics.ServiceCheckCritical, "", nil, newErr.Error())
		return nil, newErr
	}

	prop, err := c.stats.SystemState(conn)
	if err != nil {
		newErr := fmt.Errorf("Err calling SystemState: %v", err)
		sender.ServiceCheck(canConnectServiceCheckName, metrics.ServiceCheckCritical, "", nil, newErr.Error())
		return nil, newErr
	}

	serviceCheckStatus := metrics.ServiceCheckUnknown
	systemState, ok := prop.Value.Value().(string)
	if ok {
		status, ok := systemdStatusMapping[systemState]
		if ok {
			serviceCheckStatus = status
		}
	}
	sender.ServiceCheck(canConnectServiceCheckName, serviceCheckStatus, "", nil, fmt.Sprintf("Systemd status is %v", prop.Value))
	return conn, nil
}

func (c *Check) submitUnitMetrics(sender aggregator.Sender, conn *dbus.Conn) error {
	units, err := c.stats.ListUnits(conn)
	if err != nil {
		return fmt.Errorf("Error getting list of units: %v", err)
	}

	unitCounts := map[string]int{}
	for _, unit := range units {
		unitCounts[unit.ActiveState]++

		if !c.isMonitored(unit.Name) {
			continue
		}
		tags := []string{
			unitTag + ":" + unit.Name,
			unitActiveStateTag + ":" + unit.ActiveState,
			unitSubStateTag + ":" + unit.SubState,
		}
		sender.Gauge("systemd.unit.monitored", 1, "", tags)
		sender.ServiceCheck("systemd.unit.status", getServiceCheckStatus(unit.ActiveState), "", tags, "")
		c.submitMonitoredUnitMetrics(sender, conn, unit, tags)

		if unit.ActiveState != unitActiveState {
			continue
		}
		if strings.HasSuffix(unit.Name, "."+serviceSuffix) {
			c.submitServiceMetrics(sender, conn, unit, tags)
		}
	}

	for _, activeState := range unitActiveStateList {
		sender.Gauge(activeState.metricName, float64(unitCounts[activeState.activeState]), "", nil)
	}
	sender.Gauge("systemd.unit.all.count", float64(len(units)), "", nil)

	return nil
}

func (c *Check) submitMonitoredUnitMetrics(sender aggregator.Sender, conn *dbus.Conn, unit dbus.UnitStatus, tags []string) {
	unitProperties, err := c.stats.GetUnitTypeProperties(conn, unit.Name, unitTypeUnit)
	if err != nil {
		log.Errorf("Error getting unit unitProperties: %s", unit.Name)
		return
	}

	ActiveEnterTimestamp, err := getPropertyUint64(unitProperties, "ActiveEnterTimestamp")
	if err != nil {
		log.Errorf("Error getting property ActiveEnterTimestamp: %v", err)
		return
	}
	sender.Gauge("systemd.unit.uptime", float64(computeUptime(unit.ActiveState, ActiveEnterTimestamp, c.stats.TimeNanoNow())), "", tags)
}

func (c *Check) submitServiceMetrics(sender aggregator.Sender, conn *dbus.Conn, unit dbus.UnitStatus, tags []string) {
	serviceProperties, err := c.stats.GetUnitTypeProperties(conn, unit.Name, unitTypeService)
	if err != nil {
		log.Errorf("Error getting serviceProperties for service: %s", unit.Name)
		return
	}

	for _, service := range serviceUnitConfigList {
		err := sendPropertyAsGauge(sender, serviceProperties, service, tags)
		if err != nil {
			msg := fmt.Sprintf("Cannot send property '%s' for unit '%s': %v", service.propertyName, unit.Name, err)
			if service.required {
				log.Errorf(msg)
			} else {
				log.Debugf(msg)
			}
		}
	}
}

func sendPropertyAsGauge(sender aggregator.Sender, properties map[string]interface{}, service serviceUnitConfig, tags []string) error {
	if service.accountingProperty != "" {
		accounting, err := getPropertyBool(properties, service.accountingProperty)
		if err != nil {
			return err
		}
		if !accounting {
			log.Debugf("Skip sending metric due to disabled accounting. PropertyName=%s, AccountingProperty=%s, tags: %v", service.propertyName, service.accountingProperty, tags)
			return nil
		}
	}
	value, err := getPropertyUint64(properties, service.propertyName)
	if err != nil {
		return fmt.Errorf("Error getting property %s: %v", service.propertyName, err)
	}
	sender.Gauge(service.metricName, float64(value), "", tags)
	return nil
}

func computeUptime(activeState string, activeEnterTimestampMicroSec uint64, nanoNow int64) int64 {
	if activeState != unitActiveState {
		return 0
	}
	uptime := nanoNow/1000 - int64(activeEnterTimestampMicroSec)
	if uptime < 0 {
		return 0
	}
	return uptime
}

func getPropertyUint64(properties map[string]interface{}, propertyName string) (uint64, error) {
	prop, ok := properties[propertyName]
	if !ok {
		return 0, fmt.Errorf("Property %s not found", propertyName)
	}
	switch typedProp := prop.(type) {
	case uint:
		return uint64(typedProp), nil
	case uint32:
		return uint64(typedProp), nil
	case uint64:
		return typedProp, nil
	}
	return 0, fmt.Errorf("Property %s (%T) cannot be converted to uint64", propertyName, prop)
}

func getPropertyString(properties map[string]interface{}, propertyName string) (string, error) {
	prop, ok := properties[propertyName]
	if !ok {
		return "", fmt.Errorf("Property %s not found", propertyName)
	}
	propString, ok := prop.(string)
	if !ok {
		return "", fmt.Errorf("Property %s (%T) cannot be converted to string", propertyName, prop)
	}
	return propString, nil
}

func getPropertyBool(properties map[string]interface{}, propertyName string) (bool, error) {
	prop, ok := properties[propertyName]
	if !ok {
		return false, fmt.Errorf("Property %s not found", propertyName)
	}
	propString, ok := prop.(bool)
	if !ok {
		return false, fmt.Errorf("Property %s (%T) cannot be converted to bool", propertyName, prop)
	}
	return propString, nil
}

func getServiceCheckStatus(activeState string) metrics.ServiceCheckStatus {
	switch activeState {
	case "active":
		return metrics.ServiceCheckOK
	case "inactive", "failed":
		return metrics.ServiceCheckCritical
	case "activating", "deactivating":
		return metrics.ServiceCheckUnknown
	}
	return metrics.ServiceCheckUnknown
}

func (c *Check) isMonitored(unitName string) bool {
	for _, name := range c.config.instance.UnitNames {
		if name == unitName {
			return true
		}
	}
	for _, pattern := range c.config.instance.UnitRegexPatterns {
		if pattern.MatchString(unitName) {
			return true
		}
	}
	return false
}

// Configure configures the systemd checks
func (c *Check) Configure(rawInstance integration.Data, rawInitConfig integration.Data) error {
	err := c.CommonConfigure(rawInstance)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(rawInitConfig, &c.config.initConf)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(rawInstance, &c.config.instance)
	if err != nil {
		return err
	}

	for _, regexString := range c.config.instance.UnitRegexStrings {
		pattern, err := regexp.Compile(regexString)
		if err != nil {
			log.Errorf("Failed to parse systemd check option unit_regex: %s", err)
			continue
		}
		c.config.instance.UnitRegexPatterns = append(c.config.instance.UnitRegexPatterns, pattern)
	}
	return nil
}

func systemdFactory() check.Check {
	return &Check{
		stats:     &defaultSystemdStats{},
		CheckBase: core.NewCheckBase(systemdCheckName),
	}
}

func init() {
	core.RegisterCheck(systemdCheckName, systemdFactory)
}
