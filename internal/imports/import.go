package imports

import "fmt"

func stringProp(props map[string]interface{}, key string) string {
	if v, ok := props[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func Parse(source SourceType, content string) (*ImportResult, error) {
	switch source {
	case SourceHomepage:
		return ParseHomepage(content)
	case SourceHomarr:
		return ParseHomarr(content)
	case SourceHeimdall:
		return ParseHeimdall(content)
	default:
		return nil, fmt.Errorf("unknown import source: %s", source)
	}
}
