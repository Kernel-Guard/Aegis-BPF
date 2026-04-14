package console

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

//go:embed templates/*.html templates/partials/*.html
var templateFiles embed.FS

// funcMap provides template helper functions.
var funcMap = template.FuncMap{
	"timeAgo": func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		d := time.Since(*t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			m := int(d.Minutes())
			if m == 1 {
				return "1 minute ago"
			}
			return fmt.Sprintf("%d minutes ago", m)
		case d < 24*time.Hour:
			h := int(d.Hours())
			if h == 1 {
				return "1 hour ago"
			}
			return fmt.Sprintf("%d hours ago", h)
		default:
			days := int(d.Hours()) / 24
			if days == 1 {
				return "1 day ago"
			}
			return fmt.Sprintf("%d days ago", days)
		}
	},
	"truncHash": func(hash string) string {
		if len(hash) > 12 {
			return hash[:12]
		}
		return hash
	},
	"badgeClass": func(phase string) string {
		switch phase {
		case "Applied":
			return "bg-green-500/20 text-green-400 border-green-500/30"
		case "Error":
			return "bg-red-500/20 text-red-400 border-red-500/30"
		case "Pending":
			return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
		default:
			return "bg-gray-500/20 text-gray-400 border-gray-500/30"
		}
	},
	"modeClass": func(mode string) string {
		switch mode {
		case "enforce":
			return "bg-red-500/20 text-red-400 border-red-500/30"
		case "audit":
			return "bg-blue-500/20 text-blue-400 border-blue-500/30"
		default:
			return "bg-gray-500/20 text-gray-400 border-gray-500/30"
		}
	},
	"actionClass": func(action string) string {
		switch action {
		case "Allow":
			return "bg-green-500/20 text-green-400"
		case "Block":
			return "bg-red-500/20 text-red-400"
		default:
			return "bg-gray-500/20 text-gray-400"
		}
	},
	"conditionIcon": func(status string) string {
		switch status {
		case "True":
			return "text-green-400"
		case "False":
			return "text-red-400"
		default:
			return "text-yellow-400"
		}
	},
}

func parseTemplates() (*template.Template, error) {
	return template.New("").Funcs(funcMap).ParseFS(
		templateFiles,
		"templates/*.html",
		"templates/partials/*.html",
	)
}

func staticFS() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}
