import pymongo
import certifi
import json

### This code helps to add Collection into MongoDB Database.

def store_enrichment_to_db(ip_enrichment_data, collection_name):
    
    uri = "ADD MONGODB CLUSTER URL HERE"    ## ADD URL HERE. You can get it from MongoDB Server.

    client = pymongo.MongoClient(uri, ssl=True, tlsCAFile=certifi.where())
    #Getting the database instance
    db = client['ADD DATABASE NAME']    ## ADD DATABASE NAME TO CREATE/ADD
    collection = db[collection_name]    
    insert_document =  collection.insert_many(ip_enrichment_data)
    client.close()

    response = {
        "message": f"Collection {collection_name} is created in Database."
    }    
    return response

