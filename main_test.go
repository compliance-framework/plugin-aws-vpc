package main

import (
	"reflect"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
)

func TestBuildRequiredDatasetsForAclPolicies(t *testing.T) {
	required := buildRequiredDatasets(map[string][]string{
		"acl": {"/tmp/policies"},
	})

	for _, dataset := range []string{"vpcs", "subnets", "network_acls", "route_tables", "internet_gateways", "flow_logs", "log_groups", "network_interfaces"} {
		if !required[dataset] {
			t.Fatalf("expected %s to be required for acl policies", dataset)
		}
	}
}

func TestBuildRequiredDatasetsForSubnetPolicies(t *testing.T) {
	required := buildRequiredDatasets(map[string][]string{
		"subnet": {"/tmp/policies"},
	})

	for _, dataset := range []string{"vpcs", "subnets", "route_tables", "network_acls", "internet_gateways", "flow_logs", "log_groups"} {
		if !required[dataset] {
			t.Fatalf("expected %s to be required for subnet policies", dataset)
		}
	}
}

func TestBuildRequiredDatasetsForRouteTablePolicies(t *testing.T) {
	required := buildRequiredDatasets(map[string][]string{
		"rt": {"/tmp/policies"},
	})

	for _, dataset := range []string{"vpcs", "subnets", "route_tables", "internet_gateways", "vpc_endpoints", "transit_gateway_attachments"} {
		if !required[dataset] {
			t.Fatalf("expected %s to be required for route table policies", dataset)
		}
	}
}

func TestSupportedPolicyBehaviorsOnlyIncludesPrimaryVpcBundles(t *testing.T) {
	expected := []string{"vpc", "subnet", "sg", "acl", "rt"}
	if actual := supportedPolicyBehaviors(); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("supportedPolicyBehaviors() = %v, want exactly %v", actual, expected)
	}
}

func TestEvidenceActorsNameThisPlugin(t *testing.T) {
	var tool *proto.OriginActor
	for _, actor := range evidenceActors() {
		if actor.GetType() == "tool" {
			tool = actor
		}
	}
	if tool == nil {
		t.Fatal("expected a tool actor")
	}
	if got, want := tool.GetTitle(), "Continuous Compliance Framework - AWS VPC Plugin"; got != want {
		t.Fatalf("tool actor title = %q, want %q", got, want)
	}
	if len(tool.GetLinks()) != 1 {
		t.Fatalf("expected 1 tool actor link, got %d", len(tool.GetLinks()))
	}
	link := tool.GetLinks()[0]
	if got, want := link.GetHref(), "https://github.com/compliance-framework/plugin-aws-vpc"; got != want {
		t.Fatalf("tool actor link = %q, want %q", got, want)
	}
	if got, want := link.GetText(), "The Continuous Compliance Framework AWS VPC Plugin"; got != want {
		t.Fatalf("tool actor link text = %q, want %q", got, want)
	}
}
