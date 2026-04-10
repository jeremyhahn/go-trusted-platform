// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package object

// XKMSObjectAdapter wraps ObjectStorer to implement store.BlobStorer from go-xkms.
// This adapter converts between []byte and string key signatures.
type XKMSObjectAdapter struct {
	store ObjectStorer
}

// NewXKMSObjectAdapter creates a new adapter that wraps an ObjectStorer
// and implements the store.BlobStorer interface from go-xkms.
func NewXKMSObjectAdapter(store ObjectStorer) *XKMSObjectAdapter {
	return &XKMSObjectAdapter{store: store}
}

// Read implements store.BlobStorer
func (a *XKMSObjectAdapter) Read(name string) ([]byte, error) {
	return a.store.Get([]byte(name))
}

// Write implements store.BlobStorer
func (a *XKMSObjectAdapter) Write(name string, data []byte) error {
	return a.store.Save([]byte(name), data)
}

// Delete implements store.BlobStorer with string key
func (a *XKMSObjectAdapter) Delete(name string) error {
	return a.store.Delete([]byte(name))
}
