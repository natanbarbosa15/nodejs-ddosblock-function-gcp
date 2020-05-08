const retry = require("async-retry");
const { google } = require("googleapis");
const appengine = google.appengine("v1");
const compute = google.compute("v1");

// Function to create a Firewall Rule if not exists
async function createFirewallRule(ip, project, authClient) {
  // Create a new rule with default parameters
  const newRule = {
    kind: "compute#firewall",
    name: "ddosblock",
    selfLink: `projects/${project}/global/firewalls/ddosblock`,
    network: `projects/${project}/global/networks/default`,
    direction: "INGRESS",
    priority: 1,
    description: "Blocked IPs because of DDoS Attack.",
    denied: [
      {
        IPProtocol: "all",
      },
    ],
    sourceRanges: [],
  };

  // Add blocked IP to the new Rule
  newRule.sourceRanges.push(ip + "/32");

  // Create a request template with required parameters
  const request = {
    // Project ID for this request.
    project: project,
    // JSON Rule
    resource: newRule,
    // Authentication Token
    auth: authClient,
  };

  // Insert the new rule into Firewall with request template and display log if have any errors
  await compute.firewalls.insert(request);
}

// Function to update a Firewall Rule if exists
async function updateFirewallRule(ip, project, authClient, rule) {
  const blockIp = ip + "/32";

  // Check if IP to block is not already blocked
  if (!rule.sourceRanges.includes(blockIp)) {
    // Add new blocked IP to existing rule
    rule.sourceRanges.push(blockIp);

    // Create a request template with required parameters
    const request = {
      // Project ID for this request.
      project: project,
      // Name of the firewall rule to update.
      firewall: rule.name,
      // JSON Rule
      resource: rule,
      // Authentication Token
      auth: authClient,
    };

    // Update the rule into Firewall with request template and display log if have any errors
    await compute.firewalls.update(request);
  }
  // Else is already blocked
  else {
    return;
  }
}

exports.DdosBlock = async (req, res) => {
  // This method looks for the GCLOUD_PROJECT and GOOGLE_APPLICATION_CREDENTIALS
  const auth = new google.auth.GoogleAuth({
    // Scopes can be specified either as an array or as a single, space-delimited string.
    scopes: [
      "https://www.googleapis.com/auth/appengine.admin",
      "https://www.googleapis.com/auth/cloud-platform",
      "https://www.googleapis.com/auth/cloud-platform.read-only",
      "https://www.googleapis.com/auth/compute",
      "https://www.googleapis.com/auth/compute.readonly",
      "https://www.googleapis.com/auth/devstorage.full_control",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/devstorage.read_write",
    ],
  });

  // Obtain Client Authentication
  const authClient = await auth.getClient();
  // Obtain the current Project ID
  const project = await auth.getProjectId();

  // Create a request template with required parameters
  const request = {
    // Project ID for this request.
    project: project,
    // Authentication Token
    auth: authClient,
  };

  // Retry async block if generate any errors
  await retry(
    async (procedure) => {
      // Fetch current Firewall rules
      result = await compute.firewalls.list(request);
      // Get only Firewall rules from result
      const rules = result.data.items;
      // Var for update rule
      let updateRule = null;

      // Loop through rules and check if already exists "ddosblock" rule
      for (const rule of rules) {
        if (rule.name === "ddosblock") {
          updateRule = rule;
          break;
        }
      }

      // If rule not exists call function to create rule
      if (updateRule === null) {
        await createFirewallRule(req.body.ip, project, authClient).catch();
      }
      // Else call function to update rule
      else {
        await updateFirewallRule(
          req.body.ip,
          project,
          authClient,
          updateRule
        ).catch();
      }
    },
    {
      // Max number of retries
      retries: 5,
      // Min timeout for every retry = 2000 ms => 2 s
      minTimeout: 2000,
      // Max timeout for every retry = 10000 ms => 10 s
      maxTimeout: 10000,
    }
  );
  res.status(200).send("Blocked IP = " + req.body.ip);
};
