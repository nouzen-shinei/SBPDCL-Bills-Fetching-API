function downloadSBPDCLBill() {
  const CA_NUMBER = "PROVIDE_YOUR_OWN_CA_NUMBER_HERE";
  const VERCEL_CRYPTO_URL = "https://sbpdcl-bills-fetching-api.vercel.app/api/crypto";
  const EMAIL = Session.getActiveUser() .getEmail(); 
  const FOLDER_NAME = "SBPDCL Bills";
  const MAX_RETRIES = 3; 
  
  // --- HELPER 1: Ask Vercel to perform AES/RSA encryption ---
  function getCrypto(type, data, rsaKey = null) {
    const payload = { type: type, data: data };
    if (rsaKey) payload.rsa_key = rsaKey;
    
    const resp = UrlFetchApp.fetch(VERCEL_CRYPTO_URL, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    });
    
    if (resp.getResponseCode() !== 200) throw new Error("Vercel Crypto Failed: " + resp.getContentText());
    return JSON.parse(resp.getContentText());
  }

  // --- HELPER 2: Network Client with Built-in Cookie Management ---
  let cookies = {};
  let baseHeaders = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Origin": "https://wss.sbpdcl.co.in",
    "Referer": "https://wss.sbpdcl.co.in/cportal/"
  };

  function fetchSBPDCL(url, payloadObj, isStatic = false, rsaKey = null, token = null) {
    let encryptedData = isStatic 
      ? getCrypto('static', payloadObj).result 
      : JSON.stringify(getCrypto('dynamic', payloadObj, rsaKey));

    let headers = Object.assign({}, baseHeaders);
    let cookieString = Object.keys(cookies).map(k => k + '=' + cookies[k]).join('; ');
    
    if (cookieString) headers["Cookie"] = cookieString;
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    let options = {
      method: "post",
      headers: headers,
      contentType: isStatic ? "text/plain" : "application/json",
      payload: encryptedData,
      muteHttpExceptions: true
    };

    const resp = UrlFetchApp.fetch(url, options);
    
    // Automatically capture and store session cookies
    let setCookie = resp.getAllHeaders()['Set-Cookie'];
    if (setCookie) {
      let cookieArray = Array.isArray(setCookie) ? setCookie : [setCookie];
      cookieArray.forEach(c => {
        let parts = c.split(';')[0].split('=');
        if (parts.length === 2) cookies[parts[0]] = parts[1];
      });
    }
    return resp;
  }

  // --- MAIN EXECUTION WITH RETRY LOOP ---
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      // 0. Wake up the load balancer
      UrlFetchApp.fetch("https://wss.sbpdcl.co.in/cportal/", { headers: baseHeaders, muteHttpExceptions: true });

      // 1. Fetch RSA Key
      let rsaResp = fetchSBPDCL("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service", { action: "getAllWebConfigurations" }, true);
      const rsaKey = JSON.parse(rsaResp.getContentText()).enc;

      // 2. Fetch JWT Token
      let tokenResp = fetchSBPDCL("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service", { action: "getNscToken" }, false, rsaKey);
      const token = JSON.parse(tokenResp.getContentText()).access_token;

      // 3. Validate Session
      fetchSBPDCL("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service", { action: `billing/getBillValidation/${CA_NUMBER}`, method: "GET", auth: "NO", baseUrlName: "" }, false, rsaKey, token);

      // 4. Fetch Exact Database Details
      let detailsResp = fetchSBPDCL("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service", { action: "fgexternal/rest/fetchBillDetails/", method: "POST", req: { scno: CA_NUMBER }, auth: "TOKEN", baseUrlName: "", reqType: "CISENC" }, false, rsaKey, token);
      
      let detData = JSON.parse(detailsResp.getContentText());
      let rawData = detData[0].data;
      let innerJson = typeof rawData === 'string' ? JSON.parse(rawData) : rawData;
      
      let bMonthFull = innerJson.billMonth; // e.g., "06/2026"
      let mNum = parseInt(bMonthFull.split('/')[0], 10);
      let yStr = bMonthFull.split('/')[1];
      
      // FEATURE 1: Translate numerical month to full name
      const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
      let monthName = monthNames[mNum - 1];
      let fileName = `SBPDCL_Bill_${monthName}_${yStr}.pdf`;

      // 5. Setup Google Drive Folder
      let folder;
      const folders = DriveApp.getFoldersByName(FOLDER_NAME);
      folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(FOLDER_NAME);
      
      // FEATURE 2: Smart Archiving logic for duplicates
      const existingFiles = folder.getFilesByName(fileName);
      while (existingFiles.hasNext()) {
        let fileToRename = existingFiles.next();
        let suffixCounter = 1;
        let renamedFileName = fileName.replace('.pdf', '_old.pdf');

        // Loop to find an available 'old' suffix (e.g., if _old is taken, try _old2)
        while (folder.getFilesByName(renamedFileName).hasNext()) {
          suffixCounter++;
          renamedFileName = fileName.replace('.pdf', `_old${suffixCounter}.pdf`);
        }
        
        fileToRename.setName(renamedFileName);
        console.log(`Archived previous version to: ${renamedFileName}`);
      }

      // 6. Download the final PDF 
      let pdfUrl = "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD";
      let pdfPayload = {
        action: "billing/getviewbillprint",
        method: "POST",
        req: { billMonth: bMonthFull.split('/')[0], billYear: yStr, scno: CA_NUMBER, lang: "H", printtype: "PDF", modulename: "WSS", genPDF: "N", finalflag: "X" },
        auth: "TOKEN"
      };
      
      let pdfResp = fetchSBPDCL(pdfUrl, pdfPayload, false, rsaKey, token);
      let code = pdfResp.getResponseCode();
      let contentBytes = pdfResp.getContent(); 
      
      if (code === 200 && contentBytes.length > 1000) {
        let blob = Utilities.newBlob(contentBytes, 'application/pdf', fileName);
        const file = folder.createFile(blob);   
        
        MailApp.sendEmail({
          to: EMAIL,
          subject: `✅ SBPDCL Bill Saved - ${monthName} ${yStr}`,
          htmlBody: `<p>Your electricity bill was downloaded successfully.</p><p><b>File:</b> ${fileName}</p><p><b>Open in Drive:</b> <a href="${file.getUrl()}">Click here</a></p>`
        });
        
        console.log(`Success! ${fileName} saved to Drive.`);
        return; // Success! Break the retry loop and exit gracefully.
        
      } else {
        throw new Error(`PDF Endpoint Failed. HTTP ${code}. Size: ${contentBytes.length}`);
      }

    } catch (error) {
      console.error(`Attempt ${attempt} failed: ${error.toString()}`);
      if (attempt === MAX_RETRIES) {
        // Only send the failure email if it failed all 3 attempts
        MailApp.sendEmail({
          to: EMAIL,
          subject: "❌ SBPDCL Bill Download Failed",
          body: `The automation attempted ${MAX_RETRIES} times but failed to download the bill. The server might be down.\n\nError details:\n${error.toString()}`
        });
        throw error;
      }
      // If it failed but we have retries left, wait 30 seconds before trying again
      Utilities.sleep(30000);
    }
  }
}