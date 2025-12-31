// Zcash Web Wallet - Integrity Verification Bootstrap
// This minimal script verifies that served files match the repository code
// Keep this file small (<500 lines) so users can easily audit it

const REPO_OWNER = "LeakIX";
const REPO_NAME = "zcash-web-wallet";
const REPO_BRANCH = "main";
const CHECKSUMS_URL = `https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/CHECKSUMS.json`;
const VERIFICATION_DELAY_MS = 200; // Visual delay between file checks for transparency

// Files to verify (relative to frontend/)
const FILES_TO_VERIFY = [
  "js/app.js",
  "js/wasm.js",
  "js/decrypt-viewer.js",
  "js/scanner.js",
  "js/wallet.js",
  "js/addresses.js",
  "js/send.js",
  "js/views.js",
  "js/theme.js",
  "js/utils.js",
  "js/rpc.js",
  "js/constants.js",
  "js/storage/endpoints.js",
  "js/storage/notes.js",
  "js/storage/wallets.js",
  "js/storage/ledger.js",
  "css/style.css",
  "index.html",
];

class IntegrityVerifier {
  constructor() {
    this.verified = false;
    this.checksums = null;
  }

  async sha256(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async fetchFile(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to fetch ${path}: ${response.statusText}`);
    }
    return await response.text();
  }

  async fetchChecksums() {
    try {
      const response = await fetch(CHECKSUMS_URL, { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`Failed to fetch checksums: ${response.statusText}`);
      }
      return await response.json();
    } catch (error) {
      console.error("Error fetching checksums:", error);
      throw new Error(
        "Could not fetch checksums from repository. Please check your internet connection."
      );
    }
  }

  showVerificationModal(title, content, buttons) {
    return new Promise((resolve) => {
      const modalHtml = `
        <div class="modal fade" id="integrityModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1">
          <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title">${title}</h5>
              </div>
              <div class="modal-body">
                ${content}
              </div>
              <div class="modal-footer">
                ${buttons}
              </div>
            </div>
          </div>
        </div>
      `;

      document.body.insertAdjacentHTML("beforeend", modalHtml);
      const modalElement = document.getElementById("integrityModal");

      // Ensure Bootstrap is available
      if (typeof bootstrap === "undefined" || !bootstrap.Modal) {
        throw new Error(
          "Bootstrap is not loaded. Cannot display verification modal."
        );
      }

      const modal = new bootstrap.Modal(modalElement);

      modalElement.addEventListener("hidden.bs.modal", () => {
        modalElement.remove();
      });

      modal.show();
      window.integrityModalResolve = resolve;
    });
  }

  async verifyFiles() {
    const progressHtml = `
      <div class="mb-3">
        <div class="alert alert-info">
          <i class="bi bi-info-circle me-2"></i>
          <strong>Verifying Code Integrity</strong>
          <p class="mb-0 mt-2">This application is verifying that the code being served matches the code in the 
          <a href="https://github.com/${REPO_OWNER}/${REPO_NAME}" target="_blank" rel="noopener">GitHub repository</a>. 
          Each file is being hashed and compared against expected values.</p>
        </div>
      </div>
      <div class="progress mb-3" style="height: 25px;">
        <div id="verifyProgress" class="progress-bar progress-bar-striped progress-bar-animated" 
             role="progressbar" style="width: 0%">0%</div>
      </div>
      <div id="verifyStatus" class="small font-monospace"></div>
    `;

    await this.showVerificationModal(
      '<i class="bi bi-shield-check me-2"></i>Code Integrity Verification',
      progressHtml,
      '<button class="btn btn-secondary" disabled>Please wait...</button>'
    );

    const statusDiv = document.getElementById("verifyStatus");
    const progressBar = document.getElementById("verifyProgress");
    const total = FILES_TO_VERIFY.length;
    let verified = 0;

    for (let i = 0; i < FILES_TO_VERIFY.length; i++) {
      const file = FILES_TO_VERIFY[i];
      statusDiv.innerHTML += `<div class="text-muted">Verifying ${file}...</div>`;

      try {
        const content = await this.fetchFile(file);
        const actualHash = await this.sha256(content);
        const expectedHash = this.checksums.files[file];

        if (!expectedHash) {
          throw new Error(`No checksum found for ${file}`);
        }

        if (actualHash !== expectedHash) {
          throw new Error(
            `Hash mismatch for ${file}. Expected: ${expectedHash.substring(0, 32)}..., Got: ${actualHash.substring(0, 32)}...`
          );
        }

        statusDiv.lastChild.innerHTML = `<div class="text-success"><i class="bi bi-check-circle me-1"></i>${file} verified</div>`;
        verified++;
      } catch (error) {
        statusDiv.lastChild.innerHTML = `<div class="text-danger"><i class="bi bi-x-circle me-1"></i>${file} failed: ${error.message}</div>`;
        throw error;
      }

      const progress = Math.round(((i + 1) / total) * 100);
      progressBar.style.width = `${progress}%`;
      progressBar.textContent = `${progress}%`;

      // Visual delay for transparency
      await new Promise((resolve) =>
        setTimeout(resolve, VERIFICATION_DELAY_MS)
      );
    }

    return verified === total;
  }

  async showFirstTimeWarning() {
    const content = `
      <div class="alert alert-warning">
        <i class="bi bi-exclamation-triangle me-2"></i>
        <strong>First Time Visit - Important Security Notice</strong>
      </div>
      <p>This is your first time using this application (or you've cleared your browser data). Before proceeding:</p>
      <h6 class="fw-bold">How to Verify This Code</h6>
      <ol>
        <li><strong>Inspect the Source:</strong> Open your browser's developer tools (F12) and review the code.</li>
        <li><strong>Compare with Repository:</strong> Visit the 
            <a href="https://github.com/${REPO_OWNER}/${REPO_NAME}" target="_blank" rel="noopener">GitHub repository</a> 
            and compare files.</li>
        <li><strong>Verify Checksums:</strong> The checksums are fetched from 
            <a href="${CHECKSUMS_URL}" target="_blank" rel="noopener">CHECKSUMS.json</a>.</li>
        <li><strong>Build It Yourself:</strong> Clone the repo and build it locally for maximum security.</li>
      </ol>
      <div class="alert alert-info mb-0">
        <strong>Current Version:</strong> <code class="ms-2">${this.checksums.version}</code><br>
        <strong>Build Date:</strong> <code class="ms-2">${this.checksums.timestamp}</code>
      </div>
    `;

    const buttons = `
      <button class="btn btn-secondary" onclick="window.integrityModalResolve(false)">
        Cancel - I'll verify manually
      </button>
      <button class="btn btn-primary" onclick="window.integrityModalResolve(true)">
        I understand - Proceed
      </button>
    `;

    return await this.showVerificationModal(
      '<i class="bi bi-shield-exclamation me-2 text-warning"></i>Security Notice',
      content,
      buttons
    );
  }

  async showVersionChangeWarning(oldVersion, newVersion) {
    const content = `
      <div class="alert alert-danger">
        <i class="bi bi-exclamation-triangle me-2"></i>
        <strong>Code Version Has Changed!</strong>
      </div>
      <p>The code has been updated since your last visit. This could be a legitimate update or a security issue.</p>
      <div class="mb-3">
        <strong>Previous version:</strong> <code>${oldVersion}</code><br>
        <strong>New version:</strong> <code>${newVersion}</code>
      </div>
      <h6 class="fw-bold">What you should do:</h6>
      <ol>
        <li>Review the <a href="https://github.com/${REPO_OWNER}/${REPO_NAME}/compare/${oldVersion}...${newVersion}" 
            target="_blank" rel="noopener">changes on GitHub</a></li>
        <li>Check the <a href="https://github.com/${REPO_OWNER}/${REPO_NAME}/blob/main/CHANGELOG.md" 
            target="_blank" rel="noopener">CHANGELOG</a> for recent updates</li>
        <li>Verify the checksums match the repository</li>
        <li>If anything seems suspicious, do not proceed</li>
      </ol>
    `;

    const buttons = `
      <button class="btn btn-danger" onclick="window.integrityModalResolve(false)">
        Reject Update - Exit
      </button>
      <button class="btn btn-primary" onclick="window.integrityModalResolve(true)">
        Accept Update - Continue
      </button>
    `;

    return await this.showVerificationModal(
      '<i class="bi bi-shield-exclamation me-2 text-danger"></i>Version Change Detected',
      content,
      buttons
    );
  }

  showVerificationSuccess() {
    const modal = bootstrap.Modal.getInstance(
      document.getElementById("integrityModal")
    );
    if (modal) {
      modal.hide();
    }

    // Store verified version
    localStorage.setItem("verified_version", this.checksums.version);
    localStorage.setItem("verified_timestamp", Date.now().toString());

    this.verified = true;
    this.updateVerificationIndicator();
  }

  showVerificationFailure(error) {
    const content = `
      <div class="alert alert-danger">
        <i class="bi bi-x-circle me-2"></i>
        <strong>Code Integrity Verification Failed!</strong>
      </div>
      <p class="text-danger fw-bold">DO NOT USE THIS APPLICATION</p>
      <p>The code being served does not match the repository. This could indicate:</p>
      <ul>
        <li>A compromised server</li>
        <li>A man-in-the-middle attack</li>
        <li>Network issues or caching problems</li>
      </ul>
      <div class="alert alert-secondary">
        <strong>Error:</strong> <code>${error.message}</code>
      </div>
      <p class="mb-0">For your safety, please close this page and verify through other means.</p>
    `;

    const buttons = `
      <button class="btn btn-danger" onclick="window.location.href='about:blank'">
        Close Application
      </button>
    `;

    this.showVerificationModal(
      '<i class="bi bi-shield-x me-2 text-danger"></i>Verification Failed',
      content,
      buttons
    );
  }

  updateVerificationIndicator() {
    const indicator = document.getElementById("verificationIndicator");
    const indicatorMobile = document.getElementById(
      "verificationIndicatorMobile"
    );

    const buttonHTML = `
      <button class="btn btn-sm btn-outline-success verification-button" title="Code integrity verified">
        <i class="bi bi-shield-check me-1"></i>Verified
      </button>
    `;

    if (indicator) {
      indicator.innerHTML = buttonHTML;
    }

    if (indicatorMobile) {
      indicatorMobile.innerHTML = buttonHTML;
    }

    // Add event listeners to all verification buttons
    document.querySelectorAll(".verification-button").forEach((button) => {
      button.addEventListener("click", () => this.showVerificationInfo());
    });
  }

  async showVerificationInfo() {
    const verifiedTimestamp = localStorage.getItem("verified_timestamp");
    const verifiedDate = new Date(parseInt(verifiedTimestamp));

    const content = `
      <div class="alert alert-success">
        <i class="bi bi-shield-check me-2"></i>
        <strong>Code Integrity Verified</strong>
      </div>
      <p>All files have been verified against the repository checksums.</p>
      <div class="mb-3">
        <strong>Version:</strong> <code>${this.checksums.version}</code><br>
        <strong>Verified:</strong> <code>${verifiedDate.toLocaleString()}</code><br>
        <strong>Checksums Source:</strong> 
        <a href="${CHECKSUMS_URL}" target="_blank" rel="noopener" class="font-monospace small">
          ${CHECKSUMS_URL}
        </a>
      </div>
      <h6 class="fw-bold">Manual Verification</h6>
      <p class="small">To manually verify the integrity:</p>
      <ol class="small">
        <li>Open developer tools (F12) and go to the Sources tab</li>
        <li>View the JavaScript files and compare with the 
            <a href="https://github.com/${REPO_OWNER}/${REPO_NAME}/tree/${this.checksums.version}/frontend" 
            target="_blank" rel="noopener">repository</a></li>
        <li>Or clone the repo and build it yourself for complete security</li>
      </ol>
    `;

    const buttons = `
      <button class="btn btn-primary" onclick="window.integrityModalResolve(true)">
        Re-verify Now
      </button>
      <button class="btn btn-secondary" onclick="window.integrityModalResolve(false)">
        Close
      </button>
    `;

    const shouldReVerify = await this.showVerificationModal(
      '<i class="bi bi-shield-check me-2"></i>Verification Status',
      content,
      buttons
    );

    if (shouldReVerify) {
      await this.run();
    }
  }

  async run() {
    try {
      // Fetch checksums from repository
      this.checksums = await this.fetchChecksums();

      // Check if user has verified before
      const storedVersion = localStorage.getItem("verified_version");

      // Verify all files
      const allVerified = await this.verifyFiles();

      if (!allVerified) {
        throw new Error("File verification incomplete");
      }

      // Handle first time visit
      if (!storedVersion) {
        const proceed = await this.showFirstTimeWarning();
        if (!proceed) {
          window.location.href = "about:blank";
          return false;
        }
      }
      // Handle version change
      else if (storedVersion !== this.checksums.version) {
        const accept = await this.showVersionChangeWarning(
          storedVersion,
          this.checksums.version
        );
        if (!accept) {
          window.location.href = "about:blank";
          return false;
        }
      }

      this.showVerificationSuccess();
      return true;
    } catch (error) {
      console.error("Integrity verification failed:", error);
      this.showVerificationFailure(error);
      return false;
    }
  }
}

// Auto-run verification when loaded
window.integrityVerifier = new IntegrityVerifier();
