/**
 * Shopify OAuth Install Flow - Electron Frontend
 * 
 * This file demonstrates the fix for the missing shop parameter issue.
 * Integrate this code into your existing Electron renderer process.
 * 
 * Requirements:
 * - Add shop domain input field
 * - Validate shop domain format
 * - Generate OAuth URL with both clientId and shop
 * - Open URL in system browser
 */

// Example: If using React/Vue/etc, adapt this to your framework
// This example uses vanilla JavaScript for maximum compatibility

/**
 * Initialize Shopify OAuth UI
 * Call this when the Shopify tab/section loads
 */
function initShopifyOAuth() {
  const clientIdInput = document.getElementById('clientId');
  const shopInput = document.getElementById('shopDomain');
  const generateButton = document.getElementById('generateShopifyLink');
  const errorMessage = document.getElementById('shopifyError');
  const backendUrl = process.env.BACKEND_URL || 'http://localhost:3000'; // Adjust based on your config

  // Real-time validation
  function validateInputs() {
    const clientId = clientIdInput?.value.trim();
    const shop = shopInput?.value.trim();
    
    // Clear previous errors
    if (errorMessage) {
      errorMessage.textContent = '';
      errorMessage.style.display = 'none';
    }
    
    // Validate clientId
    if (!clientId || clientId.length === 0) {
      if (generateButton) generateButton.disabled = true;
      return false;
    }
    
    // Validate shop domain
    if (!shop || shop.length === 0) {
      if (generateButton) generateButton.disabled = true;
      return false;
    }
    
    // Validate shop domain format (must end with .myshopify.com)
    if (!shop.endsWith('.myshopify.com')) {
      if (errorMessage) {
        errorMessage.textContent = 'Shop domain must end with .myshopify.com';
        errorMessage.style.display = 'block';
      }
      if (generateButton) generateButton.disabled = true;
      return false;
    }
    
    // All validations passed
    if (generateButton) generateButton.disabled = false;
    return true;
  }

  // Attach event listeners for real-time validation
  if (clientIdInput) {
    clientIdInput.addEventListener('input', validateInputs);
    clientIdInput.addEventListener('blur', validateInputs);
  }
  
  if (shopInput) {
    shopInput.addEventListener('input', validateInputs);
    shopInput.addEventListener('blur', validateInputs);
  }

  // Handle generate button click
  if (generateButton) {
    generateButton.addEventListener('click', () => {
      const clientId = clientIdInput?.value.trim();
      const shop = shopInput?.value.trim();
      
      // Final validation before generating URL
      if (!validateInputs()) {
        return;
      }
      
      // Generate OAuth URL with both clientId and shop
      const oauthUrl = `${backendUrl}/shopify/auth?clientId=${encodeURIComponent(clientId)}&shop=${encodeURIComponent(shop)}`;
      
      // Open in system browser (NOT Electron's internal browser)
      const { shell } = require('electron').remote || require('@electron/remote');
      shell.openExternal(oauthUrl);
      
      // Optional: Show success message
      console.log('Opening Shopify OAuth URL:', oauthUrl);
    });
  }

  // Initial validation
  validateInputs();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initShopifyOAuth);
} else {
  initShopifyOAuth();
}
