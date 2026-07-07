# SBPDCL Bills Fetching API

Automate the download of the latest SBPDCL electricity bill with a small Vercel-hosted crypto API and a Google Apps Script job that saves the PDF to Google Drive and sends a confirmation email.

The project has two parts:

1. A Python API deployed on Vercel at `/api/crypto` that performs the encryption required by the SBPDCL portal.
2. A Google Apps Script that calls the Vercel API, talks to the SBPDCL portal, downloads the latest bill PDF, saves it in Drive, and emails the configured user.

## What This Project Does

- Logs in to the SBPDCL portal flow needed for bill retrieval.
- Fetches the current bill metadata for a given CA number.
- Downloads the PDF for the latest available bill month.
- Stores the file in a Drive folder named `SBPDCL Bills`.
- Renames older copies of the same bill so your Drive stays organized.
- Sends a confirmation email when the bill is successfully saved.
- Sends a failure email if all retry attempts fail.

## Repository Structure

- [appsscript.js](appsscript.js) - Google Apps Script entry point.
- [api/index.py](api/index.py) - Vercel serverless function for encryption.
- [docs/API.md](docs/API.md) - API reference and working notes.
- [requirements.txt](requirements.txt) - Python dependencies for the Vercel API.

## How It Works

The Google Apps Script does the orchestration:

1. It wakes up the SBPDCL portal.
2. It requests the RSA configuration from SBPDCL.
3. It calls the Vercel `/api/crypto` endpoint to encrypt payloads.
4. It gets a token from SBPDCL.
5. It validates the customer account and fetches bill metadata.
6. It downloads the bill PDF.
7. It saves the PDF into Google Drive.
8. It emails the user with the Drive link.

The Vercel API is only responsible for encryption. It does not store bill data or Google Drive files.

## Prerequisites

- A SBPDCL consumer account and CA number.
- A Google account with access to Google Apps Script and Google Drive.
- A Vercel account for hosting the crypto API.
- Basic familiarity with copying code into Google Apps Script.

## Step 1: Deploy the Vercel API

The Apps Script depends on a custom Vercel deployment. If you publish this repository publicly, every user must deploy their own copy and use their own Vercel URL.

### 1.1 Prepare the repository

Make sure these files are present in the repo:

- [api/index.py](api/index.py)
- [requirements.txt](requirements.txt)

Vercel will treat `api/index.py` as a Python serverless function and install the packages from `requirements.txt`.

### 1.2 Deploy on Vercel

You can deploy either from the Vercel dashboard or with the Vercel CLI.

#### Option A: Deploy from GitHub

1. Push the repository to GitHub.
2. In Vercel, click **Add New Project**.
3. Import the repository.
4. Keep the default Python settings if Vercel detects the function automatically.
5. Deploy the project.
6. After deployment, note your function URL.

Your endpoint will look similar to this:

`https://your-vercel-project.vercel.app/api/crypto`

#### Option B: Deploy with Vercel CLI

1. Install the CLI.
2. Run `vercel login`.
3. From the repository root, run `vercel`.
4. Follow the prompts to create or link the project.
5. Deploy to production when ready.

### 1.3 Verify the API

Test the endpoint with a POST request. A successful response confirms the API is ready for Apps Script.

Example request:

```bash
curl -X POST "https://your-vercel-project.vercel.app/api/crypto" \
	-H "Content-Type: application/json" \
	-d '{"type":"static","data":{"action":"getAllWebConfigurations"}}'
```

## Step 2: Configure Google Apps Script

Open Google Apps Script and create a new project, then paste the contents of [appsscript.js](appsscript.js).

### 2.1 Update the required configuration values

At the top of the script, update these values:

- `CA_NUMBER` - replace `PROVIDE_YOUR_OWN_CA_NUMBER_HERE` with your own SBPDCL CA number.
- `VERCEL_CRYPTO_URL` - replace `https://sbpdcl-bills-fetching-api.vercel.app/api/crypto` with your own deployed Vercel API URL.

Important: `https://sbpdcl-bills-fetching-api.vercel.app/api/crypto` is the author’s own deployed Vercel endpoint. It is only an example. Anyone using this repository must replace it with their own deployment URL.

Other script settings:

- `EMAIL` - the script uses `Session.getActiveUser().getEmail()` to send notifications to the active Google account. If your domain or account policy does not return an email address, replace this with a hard-coded email or read from a Script Property.
- `FOLDER_NAME` - the Drive folder where bills are stored.
- `MAX_RETRIES` - the number of attempts before sending the failure email.

### 2.2 Required Google services and permissions

The script uses these Google services:

- `UrlFetchApp` for HTTP requests.
- `DriveApp` for creating and managing the Drive folder.
- `MailApp` for sending confirmation and failure emails.
- `Utilities` for sleeping between retries.
- `Session` for reading the active user email address.

When you run the script for the first time, Google will ask for authorization. Approve the permissions so the script can access Drive, send mail, and make web requests.

## Step 3: Run It Manually First

Before scheduling the job, run `downloadSBPDCLBill()` once manually.

1. Open the Apps Script editor.
2. Select the `downloadSBPDCLBill` function.
3. Click **Run**.
4. Complete the authorization flow.
5. Check the execution logs if anything fails.

If the script succeeds, you should see:

- A new PDF in the `SBPDCL Bills` Drive folder.
- An email with the saved file link.

## Step 4: Schedule the Monthly Run in Google Apps Script

Use a time-driven trigger to run the script automatically once per month.

### Option A: Create the trigger from the Apps Script UI

1. Open your Apps Script project.
2. Click the **Triggers** icon on the left sidebar.
3. Click **Add Trigger**.
4. Choose the function `downloadSBPDCLBill`.
5. Set the event source to **Time-driven**.
6. Set the type to **Month timer**.
7. Choose the day of month and time window you want.
8. Save the trigger.

Recommended scheduling note:

- Run it a few days after the SBPDCL bill is usually generated, so the latest bill is available.
- Pick a consistent monthly slot, such as the 2nd or 3rd day of the month.

### Option B: Create the trigger with code

If you prefer a code-based setup, you can add a helper function like this in Apps Script and run it once manually:

```javascript
function createMonthlyTrigger() {
	ScriptApp.newTrigger('downloadSBPDCLBill')
		.timeBased()
		.onMonthDay(2)
		.atHour(9)
		.create();
}
```

This example schedules the job for the 2nd day of each month around 9 AM in the script timezone.

## Script Configuration Explained

### `CA_NUMBER`

This is your SBPDCL consumer account number. The script uses it to look up your bill and download the correct PDF.

### `VERCEL_CRYPTO_URL`

This is the Vercel API endpoint used to encrypt payloads before they are sent to SBPDCL.

The current value in the script is:

`https://sbpdcl-bills-fetching-api.vercel.app/api/crypto`

That URL belongs to the author’s deployment. Replace it with your own Vercel deployment URL after you publish your API.

### `EMAIL`

The script sends success and failure notifications to the active Google account returned by `Session.getActiveUser().getEmail()`.

If this returns an empty value in your environment, use a fixed email address or read the email from a script property.

### `FOLDER_NAME`

Bills are stored in a Drive folder with this name. If the folder already exists, the script reuses it.

### `MAX_RETRIES`

The script retries the entire flow this many times before giving up and sending a failure email.

## Drive Organization Behavior

The script keeps the Drive folder tidy:

- The file name is based on the bill month and year.
- If a bill with the same name already exists, the older copy is renamed with `_old`, `_old2`, and so on.
- The newest PDF is saved with the standard bill name.

This makes it easy to keep one clean current copy while still preserving earlier versions.

## API Overview

The Vercel service exposes one endpoint:

- `POST /api/crypto`

It accepts a JSON body with a `type` field and returns encryption output used by the Apps Script.

See [docs/API.md](docs/API.md) for the complete request and response reference.

## Troubleshooting

If the script fails, check the following first:

- Confirm that `CA_NUMBER` is correct.
- Confirm that `VERCEL_CRYPTO_URL` points to your own deployed API.
- Confirm that the Vercel API is live and returns HTTP 200.
- Confirm that the Apps Script project has authorization for Drive, Mail, and external requests.
- Confirm that the SBPDCL portal is accessible and the account is active.

Common failure causes:

- The Vercel endpoint still points to the sample deployment instead of your own.
- The Apps Script trigger runs before the bill is available.
- The active user email is unavailable in your Google Workspace policy.
- The SBPDCL portal changes a payload or encryption requirement.

## Security Notes

- Do not publish your real CA number publicly if you do not want it exposed.
- Each user should deploy their own Vercel API and use their own endpoint.
- Keep Google Drive and Apps Script permissions limited to the account that needs bill access.

## Possible Improvements

If you want to extend the project later, these are sensible additions:

- Move `CA_NUMBER`, email, and folder name into Apps Script properties.
- Add a small setup function that writes configuration values into Script Properties.
- Add a simple health-check page or endpoint for the Vercel API.
- Log the last successful month into Drive or Apps Script properties.
- Add support for multiple CA numbers if you need to manage more than one account.

## License

No license is defined in this repository yet. Add one before distributing the project widely.
