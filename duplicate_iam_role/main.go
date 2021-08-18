package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func main() {
	sourceRoleName := flag.String("source", "", "role name that we want to use as a source")
	targetRoleName := flag.String("target", "", "role name that we want to create")
	flag.Parse()

	if *sourceRoleName == "" {
		log.Fatalf("source argument cannot be empty")
		return
	}

	if *targetRoleName == "" {
		log.Fatalf("target argument cannot be empty")
		return
	}

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
		return
	}

	client := iam.NewFromConfig(cfg)

	sourceRole := GetRole(ctx, client, *sourceRoleName)
	inlinePolicies := GetInlinePolicies(ctx, client, *sourceRoleName)
	managedPolicies := GetManagedPolicies(ctx, client, *sourceRoleName)

	err = CreateRole(ctx, client, sourceRole, *targetRoleName)
	if err != nil {
		log.Fatalf("unable to create role, %v", err)
		return
	}

	if len(inlinePolicies) > 0 {
		err = AddInlinePolicies(ctx, client, *targetRoleName, inlinePolicies)
		if err != nil {
			log.Fatalf("unable to add inline policies, %v", err)
		}
	}

	if len(managedPolicies) > 0 {
		err = AddManagedPolicies(ctx, client, *targetRoleName, managedPolicies)
		if err != nil {
			log.Fatalf("unable to add managed policies, %v", err)
		}
	}
}

func GetRole(ctx context.Context, client *iam.Client, roleName string) *iam.GetRoleOutput {
	roleInput := iam.GetRoleInput{
		RoleName: &roleName,
	}
	sourceRole, err := client.GetRole(ctx, &roleInput)
	if err != nil {
		log.Fatalf("failed to get role, %v", err)
	}

	return sourceRole
}

func GetInlinePolicies(ctx context.Context, client *iam.Client, roleName string) []*iam.GetRolePolicyOutput {
	inlinePolicyNames := GetInlinePoliciesRecursive(ctx, client, roleName, "")

	if len(inlinePolicyNames) == 0 {
		return []*iam.GetRolePolicyOutput{}
	}

	var inlinePolicies []*iam.GetRolePolicyOutput

	for _, policyName := range inlinePolicyNames {
		rolePolicyInput := iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		}

		inlinePolicy, err := client.GetRolePolicy(ctx, &rolePolicyInput)
		if err != nil {
			log.Fatalf("failed to get role policy, %v", err)
		}

		inlinePolicies = append(inlinePolicies, inlinePolicy)
	}

	return inlinePolicies
}

func GetInlinePoliciesRecursive(ctx context.Context, client *iam.Client, roleName string, marker string) []string {
	params := iam.ListRolePoliciesInput{
		RoleName: &roleName,
	}

	if marker != "" {
		params.Marker = &marker
	}

	rolePolicies, err := client.ListRolePolicies(ctx, &params)
	if err != nil {
		log.Fatalf("failed to get list of role policies, %v", err)
	}

	inlinePolicyNames := rolePolicies.PolicyNames

	if rolePolicies.IsTruncated {
		inlinePolicyNames_ := GetInlinePoliciesRecursive(ctx, client, roleName, *rolePolicies.Marker)
		inlinePolicyNames = append(inlinePolicyNames, inlinePolicyNames_...)
	}

	return inlinePolicyNames
}

func GetManagedPolicies(ctx context.Context, client *iam.Client, roleName string) []types.AttachedPolicy {
	managedPolicies := GetManagedPoliciesRecursive(ctx, client, roleName, "")
	return managedPolicies
}

func GetManagedPoliciesRecursive(ctx context.Context, client *iam.Client, roleName string, marker string) []types.AttachedPolicy {
	params := iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	}

	if marker != "" {
		params.Marker = &marker
	}

	attachedRolePolicies, err := client.ListAttachedRolePolicies(ctx, &params)
	if err != nil {
		log.Fatalf("failed to get list of attached role policies, %v", err)
	}

	managedPolicies := attachedRolePolicies.AttachedPolicies

	if attachedRolePolicies.IsTruncated {
		managedPolicies_ := GetManagedPoliciesRecursive(ctx, client, roleName, *attachedRolePolicies.Marker)
		managedPolicies = append(managedPolicies, managedPolicies_...)
	}

	return managedPolicies
}

func CreateRole(ctx context.Context, client *iam.Client, sourceRole *iam.GetRoleOutput, targetRoleName string) error {
	params := iam.CreateRoleInput{
		Path:               sourceRole.Role.Path,
		RoleName:           &targetRoleName,
		Description:        sourceRole.Role.Description,
		MaxSessionDuration: sourceRole.Role.MaxSessionDuration,
		Tags:               sourceRole.Role.Tags,
	}

	assumeRolePolicyDocument, err := url.PathUnescape(*sourceRole.Role.AssumeRolePolicyDocument)
	if err != nil {
		return err
	}

	params.AssumeRolePolicyDocument = &assumeRolePolicyDocument

	if sourceRole.Role.PermissionsBoundary != nil {
		params.PermissionsBoundary = sourceRole.Role.PermissionsBoundary.PermissionsBoundaryArn
	} else {
		params.PermissionsBoundary = nil
	}

	_, err = client.CreateRole(ctx, &params)
	if err != nil {
		return err
	}

	return nil
}

func AddInlinePolicies(ctx context.Context, client *iam.Client, targetRoleName string, inlinePolicies []*iam.GetRolePolicyOutput) error {
	for _, policy := range inlinePolicies {
		params := iam.PutRolePolicyInput{
			RoleName:   &targetRoleName,
			PolicyName: policy.PolicyName,
		}

		policyDocument, err := url.PathUnescape(*policy.PolicyDocument)
		if err != nil {
			params.PolicyDocument = &policyDocument
		}

		_, err = client.PutRolePolicy(ctx, &params)
		if err != nil {
			fmt.Println(fmt.Errorf("failed to add inline policy, %v", err))
		}
	}

	return nil
}

func AddManagedPolicies(ctx context.Context, client *iam.Client, targetRoleName string, managedPolicies []types.AttachedPolicy) error {
	for _, policy := range managedPolicies {
		params := iam.AttachRolePolicyInput{
			RoleName:  &targetRoleName,
			PolicyArn: policy.PolicyArn,
		}

		_, err := client.AttachRolePolicy(ctx, &params)
		if err != nil {
			fmt.Println(fmt.Errorf("failed to add managed policy, %v", err))
		}
	}

	return nil
}
