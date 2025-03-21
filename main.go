package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/compliance-framework/plugin-azure-networking-security/internal"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	startTime := time.Now()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		l.logger.Error("unable to get Azure credentials", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	client, err := armnetwork.NewSecurityGroupsClient(os.Getenv("AZURE_SUBSCRIPTION_ID"), cred, nil)
	if err != nil {
		l.logger.Error("unable to create Azure security groups client", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	// Get security groups
	pager := client.NewListAllPager(nil)
	var securityGroups []map[string]interface{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			l.logger.Error("unable to list security groups", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		// Parse security groups
		for _, group := range page.Value {
			var tags []Tag
			for key, value := range group.Tags {
				tags = append(tags, Tag{Key: key, Value: *value})
			}

			// Flatten properties for easier reference in policies
			properties := map[string]interface{}{
				"securityRules":        group.Properties.SecurityRules,
				"defaultSecurityRules": group.Properties.DefaultSecurityRules,
				"provisioningState":    group.Properties.ProvisioningState,
			}

			subjectAttributeMap := map[string]string{
				"type":          "aws",
				"service":       "security-group",
				"instance-id":   *group.ID,
				"instance-name": *group.Name,
			}
			subjects := []*proto.SubjectReference{
				{
					Type:       "aws-security-group",
					Attributes: subjectAttributeMap,
					Title:      internal.StringAddressed("AWS Security Group"),
					Props: []*proto.Property{
						{
							Name:  "security-group-id",
							Value: *group.ID,
						},
						{
							Name:  "security-group-name",
							Value: *group.Name,
						},
					},
				},
			}
			actors := []*proto.OriginActor{
				{
					Title: "The Continuous Compliance Framework",
					Type:  "assessment-platform",
					Links: []*proto.Link{
						{
							Href: "https://compliance-framework.github.io/docs/",
							Rel:  internal.StringAddressed("reference"),
							Text: internal.StringAddressed("The Continuous Compliance Framework"),
						},
					},
				},
				{
					Title: "Continuous Compliance Framework - Local SSH Plugin",
					Type:  "tool",
					Links: []*proto.Link{
						{
							Href: "https://github.com/compliance-framework/plugin-local-ssh",
							Rel:  internal.StringAddressed("reference"),
							Text: internal.StringAddressed("The Continuous Compliance Framework' Local SSH Plugin"),
						},
					},
				},
			}
			components := []*proto.ComponentReference{
				{
					Identifier: "common-components/aws-security-group",
				},
			}

			activities := make([]*proto.Activity, 0)
			findings := make([]*proto.Finding, 0)
			observations := make([]*proto.Observation, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				// Explicitly reset steps to make things readable
				steps := make([]*proto.Step, 0)
				steps = append(steps, &proto.Step{
					Title:       "Compile policy bundle",
					Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
				})
				steps = append(steps, &proto.Step{
					Title:       "Execute policy bundle",
					Description: "Using previously collected JSON-formatted SSH configuration, execute the compiled policies",
				})
				activities = append(activities, &proto.Activity{
					Title:       "Execute policy",
					Description: "Prepare and compile policy bundles, and execute them using the prepared SSH configuration data",
					Steps:       steps,
				})
				results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "compliance_plugin", map[string]interface{}{
					"SecurityGroupID":      *group.ID,
					"Location":             *group.Location,
					"Name":                 *group.Name,
					"Properties":           properties,
					"Tags":                 tags,
					"Type":                 *group.Type,
					"DefaultSecurityRules": group.Properties.DefaultSecurityRules,
					"SecurityRules":        group.Properties.SecurityRules,
					"ProvisioningState":    group.Properties.ProvisioningState,
				})
				if err != nil {
					l.logger.Error("policy evaluation failed", "error", err)
					evalStatus = proto.ExecutionStatus_FAILURE
					accumulatedErrors = errors.Join(accumulatedErrors, err)
					continue
				}

				for _, result := range results {
					// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
					// This acts as an identifier to show the history of an observation.
					observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
						"type":        "observation",
						"policy":      result.Policy.Package.PurePackage(),
						"policy_file": result.Policy.File,
						"policy_path": policyPath,
					})
					observationUUID, err := sdk.SeededUUID(observationUUIDMap)
					if err != nil {
						accumulatedErrors = errors.Join(accumulatedErrors, err)
						// We've been unable to do much here, but let's try the next one regardless.
						continue
					}

					// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
					// This acts as an identifier to show the history of a finding.
					findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
						"type":        "finding",
						"policy":      result.Policy.Package.PurePackage(),
						"policy_file": result.Policy.File,
						"policy_path": policyPath,
					})
					findingUUID, err := sdk.SeededUUID(findingUUIDMap)
					if err != nil {
						accumulatedErrors = errors.Join(accumulatedErrors, err)
						// We've been unable to do much here, but let's try the next one regardless.
						continue
					}

					observation := proto.Observation{
						ID:         uuid.New().String(),
						UUID:       observationUUID.String(),
						Collected:  timestamppb.New(startTime),
						Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
						Origins:    []*proto.Origin{{Actors: actors}},
						Subjects:   subjects,
						Activities: activities,
						Components: components,
						RelevantEvidence: []*proto.RelevantEvidence{
							{
								Description: fmt.Sprintf("Policy %v was executed against the Azure Security Group configuration, using the Azure Security Group Compliance Plugin", result.Policy.Package.PurePackage()),
							},
						},
					}

					newFinding := func() *proto.Finding {
						return &proto.Finding{
							ID:        uuid.New().String(),
							UUID:      findingUUID.String(),
							Collected: timestamppb.New(time.Now()),
							Labels: map[string]string{
								"type":          "azure",
								"service":       "security-groups",
								"instance-id":   *group.ID,
								"instance-name": *group.Name,
								"_policy":       result.Policy.Package.PurePackage(),
								"_policy_path":  result.Policy.File,
							},
							Origins:             []*proto.Origin{{Actors: actors}},
							Subjects:            subjects,
							Components:          components,
							RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
							Controls:            nil,
						}
					}

					// There are no violations reported from the policies.
					// We'll send the observation back to the agent
					if len(result.Violations) == 0 {

						observation.Title = internal.StringAddressed("The plugin succeeded. No compliance issues to report.")
						observation.Description = "The plugin policies did not return any violations. The configuration is in compliance with policies."
						observations = append(observations, &observation)

						finding := newFinding()
						finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
						finding.Description = fmt.Sprintf("No violations were found on the %s policy within the Azure Security Groups Compliance Plugin.", result.Policy.Package.PurePackage())
						finding.Status = &proto.FindingStatus{
							State: runner.FindingTargetStatusSatisfied,
						}
						findings = append(findings, finding)
						continue
					}

					// There are violations in the policy checks.
					// We'll send these observations back to the agent
					if len(result.Violations) > 0 {
						observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
						observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the Azure Security groups Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
						observations = append(observations, &observation)

						for _, violation := range result.Violations {
							finding := newFinding()
							finding.Title = violation.Title
							finding.Description = violation.Description
							finding.Remarks = internal.StringAddressed(violation.Remarks)
							finding.Status = &proto.FindingStatus{
								State: runner.FindingTargetStatusNotSatisfied,
							}
							findings = append(findings, finding)
						}
					}
				}

			}
			if err = apiHelper.CreateObservations(ctx, observations); err != nil {
				l.logger.Error("Failed to send observations", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			if err = apiHelper.CreateFindings(ctx, findings); err != nil {
				l.logger.Error("Failed to send findings", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

		}
	}

	l.logger.Debug("evaluating data", securityGroups)
	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("Initiating Azure network security plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
