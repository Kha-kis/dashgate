package handlers

import (
	"net/http"

	"dashgate/internal/auth"
	"dashgate/internal/server"
)

// DependenciesHandler returns the service dependency graph as JSON.
func DependenciesHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		type DepNode struct {
			Name       string   `json:"name"`
			Icon       string   `json:"icon"`
			Status     string   `json:"status"`
			DependsOn  []string `json:"depends_on"`
			DependedBy []string `json:"depended_by"`
		}

		app.ConfigMu.RLock()
		defer app.ConfigMu.RUnlock()

		// Build dependency map
		nodes := make(map[string]*DepNode)

		// First pass: collect all apps
		for _, cat := range app.Config.Categories {
			for _, a := range cat.Apps {
				nodes[a.Name] = &DepNode{
					Name:       a.Name,
					Icon:       a.Icon,
					Status:     a.Status,
					DependsOn:  a.DependsOn,
					DependedBy: []string{},
				}
			}
		}

		// Second pass: compute reverse dependencies
		for _, node := range nodes {
			for _, dep := range node.DependsOn {
				if target, ok := nodes[dep]; ok {
					target.DependedBy = append(target.DependedBy, node.Name)
				}
			}
		}

		// Convert to slice
		result := make([]*DepNode, 0, len(nodes))
		for _, node := range nodes {
			result = append(result, node)
		}

		respondJSON(w, http.StatusOK, result)
	}
}
