package ascii

import (
	"fmt"
	"strings"
	"github.com/helviojunior/infrachart/internal/version"
)

// Logo returns the infrachart ascii logo
func Logo() string {
	txt := `                                    
{R}Infra
{GR}  |
{GR}  o-- {G}Enumeration
{GR}  |       |\
{GR}  |       | \
{GR}  |       |  \
{GR}  |     {P}Flow {O}Chart
{GR}  |
{GR}  o-- {B}v{G}`

	v := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
	txt += v + "{W}"
	txt = strings.Replace(txt, "{GR}", "\033[97m", -1)
	txt = strings.Replace(txt, "{R}", "\033[91m", -1)
	txt = strings.Replace(txt, "{P}", "\033[95m", -1)
	txt = strings.Replace(txt, "{G}", "\033[96m", -1)
	txt = strings.Replace(txt, "{B}", "\033[36m", -1)
	txt = strings.Replace(txt, "{O}", "\033[33m", -1)
	txt = strings.Replace(txt, "{W}", "\033[0m", -1)
	return fmt.Sprintln(txt)
}

// LogoHelp returns the logo, with help
func LogoHelp(s string) string {
	return Logo() + "\n\n" + s
}
