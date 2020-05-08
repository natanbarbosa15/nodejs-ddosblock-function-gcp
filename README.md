# NodeJS DDoS Block function for Google Cloud Platform
NodeJS DDoS Block function to make API calls for Google Cloud Platform Firewall and Google App Engine Firewall.

To make use of this function implement on Google Cloud Functions with NodeJS 10+ engine, copy and paste "index.js" and "package.json", or use Cloud Source Repositories. Make sure the Cloud Function use Service Account that has role "App Engine administrator" for App Engine Firewall, and/or role "Compute security administrator" for Google Cloud Firewall.

This function use NodeJS Google Client API librariries to create and update Firewall rules, and "async-retry" library, if function fail to execute, will retry again soon.

Configuration of async retry is in this coding block in near to the end of "index.js" file, you can edit to your specific needs:
```
{
    // Max number of retries
    retries: 5,
    // Min timeout for every retry = 2000 ms => 2 s
    minTimeout: 2000,
    // Max timeout for every retry = 10000 ms => 10 s
    maxTimeout: 10000,
}
```