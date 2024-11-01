package kvstore

// func TestGetByAuthorizationURL(t *testing.T) {

// 	serializers := []serializer.Serializer[*entities.ACMEAuthorization]{
// 		serializer.NewJSONSerializer[*entities.ACMEAuthorization](),
// 		serializer.NewYAMLSerializer[*entities.ACMEAuthorization](),
// 	}

// 	for _, serializer := range serializers {

// 		params := aferoTestParams[*entities.ACMEAuthorization]()
// 		params.Partition = acme_authorization_partition
// 		params.Serializer = serializer
// 		params.Fs = afero.NewOsFs()

// 		authorizationDAO, err := NewACMEAuthorizationDAO(params)
// 		assert.Nil(t, err)

// 		// Create new org
// 		auth := &entities.ACMEAuthorization{
// 			Status: "status-test",
// 			Identifier: entities.ACMEIdentifier{
// 				Type:  "test-type",
// 				Value: "test-value",
// 			},
// 			Expires: time.Now().String(),
// 			URL:     "http://test.com",
// 		}
// 		err = authorizationDAO.Save(auth)
// 		assert.Nil(t, err)

// 		// Ensure it exists
// 		expected := fmt.Sprintf("%s/%s/%d.json", params.RootDir, acme_authorization_partition, auth.ID)
// 		_, err = params.Fs.Stat(expected)
// 		assert.Nil(t, err)

// 		// // Ensure GetAuthorizationByURL works
// 		// referencedEntity, err := authorizationDAO.GetAuthorizationByURL("http://test.com", datastore.CONSISTENCY_LOCAL)
// 		// assert.Nil(t, err)
// 		// assert.Equal(t, auth.ID, referencedEntity.ID)

// 		// Retrieve the org
// 		persisted, err := authorizationDAO.Get(auth.ID, datastore.CONSISTENCY_LOCAL)
// 		assert.Nil(t, err)
// 		assert.True(t, persisted.ID == auth.ID)

// 		// Delete the org
// 		err = authorizationDAO.Delete(auth)
// 		assert.Nil(t, err)

// 		// Ensure it's deleted
// 		_, err = authorizationDAO.Get(auth.ID, datastore.CONSISTENCY_LOCAL)
// 		assert.NotNil(t, err)
// 		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
// 	}
// }
