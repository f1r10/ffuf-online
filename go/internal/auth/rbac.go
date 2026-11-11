package auth

import "strings"

// Role is a tenant role or the orthogonal platform role.
type Role string

// Tenant roles, ordered from least to most privileged:
// read_only < analyst < researcher < org_admin < org_owner.
const (
	RoleReadOnly   Role = "read_only"
	RoleAnalyst    Role = "analyst"
	RoleResearcher Role = "researcher"
	RoleOrgAdmin   Role = "org_admin"
	RoleOrgOwner   Role = "org_owner"

	// RolePlatform is a platform super administrator. It is orthogonal to the
	// tenant roles: it grants platform-wide actions and implies every tenant
	// action, but no tenant role ever grants a platform action.
	RolePlatform Role = "platform"
)

var roleRank = map[Role]int{
	RoleReadOnly:   0,
	RoleAnalyst:    1,
	RoleResearcher: 2,
	RoleOrgAdmin:   3,
	RoleOrgOwner:   4,
	RolePlatform:   5,
}

// TenantRoles lists the roles a tenant membership may hold, most privileged
// last.
var TenantRoles = []Role{RoleReadOnly, RoleAnalyst, RoleResearcher, RoleOrgAdmin, RoleOrgOwner}

// Rank returns the privilege rank of a role (higher is more privileged). An
// unknown role ranks -1.
func (r Role) Rank() int {
	if v, ok := roleRank[r]; ok {
		return v
	}
	return -1
}

// ValidRole reports whether s names a known role.
func ValidRole(s string) bool {
	_, ok := roleRank[Role(s)]
	return ok
}

// ValidTenantRole reports whether s names a role a membership may hold.
func ValidTenantRole(s string) bool {
	for _, r := range TenantRoles {
		if string(r) == s {
			return true
		}
	}
	return false
}

// Action is a permission checked server-side for every request.
type Action string

// The complete, documented action list.
const (
	ActionProjectRead    Action = "project:read"
	ActionProjectWrite   Action = "project:write"
	ActionScopeWrite     Action = "scope:write"
	ActionScopeAuthorize Action = "scope:authorize" // org_owner only
	ActionAssetRead      Action = "asset:read"
	ActionAssetWrite     Action = "asset:write"
	ActionFindingRead    Action = "finding:read"
	ActionFindingWrite   Action = "finding:write"
	ActionFindingValidate Action = "finding:validate" // researcher+
	ActionTaskRead       Action = "task:read"
	ActionWorkerManage   Action = "worker:manage" // org_admin+
	ActionAuditRead      Action = "audit:read"    // org_admin+
	ActionMemberManage   Action = "member:manage" // org_admin+
	ActionUsageRead      Action = "usage:read"

	// Platform actions are granted only to RolePlatform.
	ActionPlatformAdmin        Action = "platform:admin"
	ActionPlatformTenantManage Action = "platform:tenant:manage"
)

// minRank maps a tenant action to the lowest tenant role that holds it.
var minRank = map[Action]int{
	ActionProjectRead:     0, // read_only
	ActionAssetRead:       0,
	ActionFindingRead:     0,
	ActionTaskRead:        0,
	ActionUsageRead:       0,
	ActionProjectWrite:    1, // analyst
	ActionAssetWrite:      1,
	ActionFindingWrite:    1,
	ActionScopeWrite:      2, // researcher
	ActionFindingValidate: 2,
	ActionWorkerManage:    3, // org_admin
	ActionAuditRead:       3,
	ActionMemberManage:    3,
	ActionScopeAuthorize:  4, // org_owner
}

var platformActions = map[Action]bool{
	ActionPlatformAdmin:        true,
	ActionPlatformTenantManage: true,
}

// IsPlatform reports whether a is a platform-scoped action.
func (a Action) IsPlatform() bool { return platformActions[a] }

// Known reports whether a is part of the documented action list.
func (a Action) Known() bool {
	if _, ok := minRank[a]; ok {
		return true
	}
	return platformActions[a]
}

// Can reports whether a principal with the given role may perform action.
//
// It is the single place RBAC is decided; handlers never inspect roles.
func Can(role Role, action Action) bool {
	if action.IsPlatform() {
		// Only the platform role grants platform actions. A tenant admin
		// therefore never acquires platform-wide access.
		return role == RolePlatform
	}
	if role == RolePlatform {
		return true
	}
	min, ok := minRank[action]
	if !ok {
		return false
	}
	return role.Rank() >= min
}

// AllActions returns the documented action list in a stable order.
func AllActions() []Action {
	return []Action{
		ActionProjectRead, ActionProjectWrite,
		ActionScopeWrite, ActionScopeAuthorize,
		ActionAssetRead, ActionAssetWrite,
		ActionFindingRead, ActionFindingWrite, ActionFindingValidate,
		ActionTaskRead,
		ActionWorkerManage, ActionAuditRead, ActionMemberManage, ActionUsageRead,
		ActionPlatformAdmin, ActionPlatformTenantManage,
	}
}

// ParseRole normalises a role string.
func ParseRole(s string) Role { return Role(strings.ToLower(strings.TrimSpace(s))) }
