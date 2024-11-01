package acme

import (
	"net/http"
	"testing"
)

func TestParseNextLinkHeaderFromRequest(t *testing.T) {
	testCases := []struct {
		name      string
		req       *http.Request
		expected  int
		expectErr bool
	}{
		{
			name: "Single Link Header with rel=next",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>; rel="next"`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Multiple Link Headers, one with rel=next",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1235>; rel="prev"`,
						`<https://client.example.com/resource/1234>; rel="next"`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "No Link Headers",
			req: &http.Request{
				Header: http.Header{},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "Link Header without rel=next",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1235>; rel="prev"`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "Malformed Link Header",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`https://client.example.com/resource/1234; rel="next"`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "Link Header with Empty URI",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<>; rel="next"`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "Rel Parameter with Different Case",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>; rel="Next"`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Unquoted rel Parameter",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>; rel=next`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Whitespace Variations",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						` <https://client.example.com/resource/1234> ; rel = "next" `,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Multiple Parameters",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>; rel="next"; type="text/html"`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Multiple rel Parameters",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>; rel="alternate next"`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Comma Inside Quoted String",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>; title="Title, with comma"; rel="next"`,
					},
				},
			},
			expected:  1234,
			expectErr: false,
		},
		{
			name: "Link Header with No Parameters",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/1234>`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "Link Header with rel=next but Missing URI",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`; rel="next"`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "Non-integer ID",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/resource/abc>; rel="next"`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
		{
			name: "ID Not in Last Path Segment",
			req: &http.Request{
				Header: http.Header{
					"Link": []string{
						`<https://client.example.com/1234/resource>; rel="next"`,
					},
				},
			},
			expected:  0,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nextID, err := parseNextLinkHeaderFromRequest(tc.req)
			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect error, got: %v", err)
				}
				if nextID != tc.expected {
					t.Errorf("Expected next ID '%d', got '%d'", tc.expected, nextID)
				}
			}
		})
	}
}
