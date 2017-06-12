package route

// RouteRuleChecker checks specific rules about a route.
type RouteRuleChecker interface {
}

// RouteValidator ensures the rules around routes are met.
type RouteValidator struct {
	checker RouteRuleChecker
}

// CertChecker (?) checks certificates / identities
// BuildHop -> uses CertChecker to build identity for hop, then
// assigns it to a new parsed struct. also need to build pointers
// to the Interface object for the interfaces, if it's us we're referring to.
