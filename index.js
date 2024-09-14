const AWS = require("aws-sdk");
const SNS = new AWS.SNS();
const cloudwatch = new AWS.CloudWatch();
const cloudwatchlogs = new AWS.CloudWatchLogs();

let CloudTrail_LogGroup = "xxxxxxxx"; // Your CloudTrail log group name
let SNS_Topis = "arn:aws:sns:xxx:xxx:xxx"; // Replace with your SNS Topic ARN

exports.handler = async (event) => {
  let message = "";

  // Check if the event source is from CloudWatch Alarm
  if (event.source === "aws.cloudwatch" && event.alarmArn) {
    // Query CloudWatch Logs Insights to fetch the relevant CloudTrail event
    const logGroupName = CloudTrail_LogGroup;
    const queryParams = {
      logGroupName,
      startTime: Date.now() - 60000 * 30, // Query last 15 minutes (adjust as needed)
      endTime: Date.now(),
      queryString: `fields @timestamp, @message, @logStream, @log
                    | filter @message like /"ConsoleLogin":"Success"/
                    | sort @timestamp desc
                    | limit 1`,
    };

    try {
      const data = await cloudwatchlogs.startQuery(queryParams).promise();
      const queryId = data.queryId;

      // Wait for the query to complete
      const queryResult = await waitForQuery(queryId);
      console.log("Query Result:", JSON.stringify(queryResult, null, 2));

      const loginEvent = queryResult.results[0]; // Extract relevant details

      if (loginEvent) {
        const logMessage = getFieldValue(loginEvent, "@message") || "N/A";
        let parsedLogMessage;

        // Try parsing the log message as JSON
        try {
          parsedLogMessage = JSON.parse(logMessage);
        } catch (error) {
          console.error("Error parsing log message JSON:", error);
          message = `Error parsing log message: ${error.message}`;
        }

        if (parsedLogMessage) {
          const eventTime = getFieldValue(loginEvent, "@timestamp") || "N/A";
          const userType = parsedLogMessage.userIdentity.type || "N/A";
          const sourceIPAddress = parsedLogMessage.sourceIPAddress || "N/A";
          const userARN = parsedLogMessage.userIdentity.arn || "N/A";
          const mfaUsed =
            parsedLogMessage.additionalEventData?.MFAUsed || "N/A";
          const mfaID =
            parsedLogMessage.additionalEventData?.MFAIdentifier || "N/A";

          // Create the message in table format
          message = `
            AWS Console Sign In Event Details:
            
            Time: ${eventTime}
            User: ${userType}
            Source IP: ${sourceIPAddress}
            User ARN: ${userARN}
            MFA Used: ${mfaUsed}
            MFA Type: ${mfaID}
            `;
        }
      } else {
        console.log(loginEvent);
        message = "No relevant login event found.";
      }
    } catch (error) {
      console.error("Error querying CloudWatch Logs Insights:", error);
      message = `Error querying CloudWatch Logs: ${error.message}`;
    }
  } else {
    message = "No relevant CloudWatch event received.";
  }

  // Define SNS publish parameters
  const snsParams = {
    Message: message,
    TopicArn: SNS_Topis,
    Subject: "AWS Console Sign In Alert",
  };

  try {
    // Publish the message to SNS
    await SNS.publish(snsParams).promise();
    // Set the alarm state back to OK
    await setAlarmStateToOK(event.alarmArn);
    return { statusCode: 200, body: "Message sent to SNS topic successfully" };
  } catch (error) {
    console.error("Error sending message to SNS:", error);
    return { statusCode: 500, body: `Error: ${error.message}` };
  }
};

// Helper function to wait for the query result
async function waitForQuery(queryId) {
  const params = { queryId };
  let status;
  let result;

  do {
    await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait for 2 seconds before checking the status
    result = await cloudwatchlogs.getQueryResults(params).promise();
    status = result.status;
  } while (status === "Running");

  if (status === "Complete") {
    return result;
  } else {
    throw new Error("Query failed");
  }
}

// Function to extract a field value from the query result
function getFieldValue(result, fieldName) {
  const field = result.find((item) => item.field === fieldName);
  return field ? field.value : null;
}

// Function to set the alarm state to OK
async function setAlarmStateToOK(alarmArn) {
  const alarmName = alarmArn.split(":").pop(); // Extract the alarm name from the ARN

  const params = {
    AlarmName: alarmName, // The name of the alarm to set the state
    StateValue: "OK", // Set the alarm state to 'OK'
    StateReason: "Manual reset after processing SNS message.",
  };

  try {
    await cloudwatch.setAlarmState(params).promise();
    console.log(`Alarm ${alarmName} state set to OK.`);
  } catch (error) {
    console.error(`Failed to set alarm state to OK for ${alarmName}:`, error);
  }
}
