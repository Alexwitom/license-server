# Shopify OAuth Install Flow Fix

## Problem
Backend requires both `clientId` and `shop` query parameters, but Electron UI was only sending `clientId`, causing:
```
"shop query parameter is required"
```

## Solution
Add shop domain input field and validation to your existing Shopify OAuth UI.

---

## Integration Guide

### Step 1: Add Shop Domain Input Field

Add this input field to your existing Shopify UI form (wherever you have the clientId input):

```html
<!-- Add this input field -->
<div class="form-group">
  <label for="shopDomain">Shop Domain *</label>
  <input 
    type="text" 
    id="shopDomain" 
    name="shopDomain" 
    placeholder="mystore.myshopify.com"
    required
  />
  <small class="input-description">
    Your Shopify store domain (must end with .myshopify.com)
  </small>
  <div id="shopifyError" class="error-message"></div>
</div>
```

### Step 2: Add Validation Logic

Add this JavaScript validation function to your existing code:

```javascript
function validateShopifyInputs() {
  const clientId = document.getElementById('clientId')?.value.trim();
  const shop = document.getElementById('shopDomain')?.value.trim();
  const generateButton = document.getElementById('generateShopifyLink');
  const errorMessage = document.getElementById('shopifyError');
  
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

// Attach real-time validation
document.getElementById('clientId')?.addEventListener('input', validateShopifyInputs);
document.getElementById('shopDomain')?.addEventListener('input', validateShopifyInputs);
document.getElementById('shopDomain')?.addEventListener('blur', validateShopifyInputs);
```

### Step 3: Update Generate Button Handler

Update your existing "Generate Shopify Install Link" button handler:

```javascript
// OLD CODE (missing shop parameter):
// const oauthUrl = `${backendUrl}/shopify/auth?clientId=${clientId}`;

// NEW CODE (includes shop parameter):
document.getElementById('generateShopifyLink')?.addEventListener('click', () => {
  const clientId = document.getElementById('clientId')?.value.trim();
  const shop = document.getElementById('shopDomain')?.value.trim();
  
  // Validate inputs
  if (!validateShopifyInputs()) {
    return;
  }
  
  // Generate OAuth URL with BOTH clientId and shop
  const backendUrl = 'YOUR_BACKEND_URL'; // Replace with your actual backend URL
  const oauthUrl = `${backendUrl}/shopify/auth?clientId=${encodeURIComponent(clientId)}&shop=${encodeURIComponent(shop)}`;
  
  // Open in system browser (NOT Electron's internal browser)
  const { shell } = require('electron').remote || require('@electron/remote') || require('electron');
  shell.openExternal(oauthUrl);
});
```

---

## Framework-Specific Examples

### React Component

```jsx
import React, { useState } from 'react';
const { shell } = require('electron').remote || require('@electron/remote') || require('electron');

function ShopifyOAuthForm() {
  const [clientId, setClientId] = useState('');
  const [shopDomain, setShopDomain] = useState('');
  const [error, setError] = useState('');
  const backendUrl = 'YOUR_BACKEND_URL'; // Replace with your actual backend URL

  const validateInputs = () => {
    if (!clientId.trim()) {
      setError('Client ID is required');
      return false;
    }
    if (!shopDomain.trim()) {
      setError('Shop domain is required');
      return false;
    }
    if (!shopDomain.endsWith('.myshopify.com')) {
      setError('Shop domain must end with .myshopify.com');
      return false;
    }
    setError('');
    return true;
  };

  const handleGenerate = () => {
    if (!validateInputs()) return;
    
    const oauthUrl = `${backendUrl}/shopify/auth?clientId=${encodeURIComponent(clientId)}&shop=${encodeURIComponent(shopDomain)}`;
    shell.openExternal(oauthUrl);
  };

  const isFormValid = clientId.trim() && shopDomain.trim() && shopDomain.endsWith('.myshopify.com');

  return (
    <div>
      <h2>Shop → Shopify</h2>
      
      <div>
        <label>Client ID *</label>
        <input
          type="text"
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          placeholder="Enter your client ID"
        />
      </div>

      <div>
        <label>Shop Domain *</label>
        <input
          type="text"
          value={shopDomain}
          onChange={(e) => setShopDomain(e.target.value)}
          placeholder="mystore.myshopify.com"
        />
        <small>Your Shopify store domain (must end with .myshopify.com)</small>
        {error && <div className="error">{error}</div>}
      </div>

      <button onClick={handleGenerate} disabled={!isFormValid}>
        Generate Shopify Install Link
      </button>
    </div>
  );
}
```

### Vue Component

```vue
<template>
  <div>
    <h2>Shop → Shopify</h2>
    
    <div>
      <label>Client ID *</label>
      <input
        v-model="clientId"
        type="text"
        placeholder="Enter your client ID"
      />
    </div>

    <div>
      <label>Shop Domain *</label>
      <input
        v-model="shopDomain"
        type="text"
        placeholder="mystore.myshopify.com"
      />
      <small>Your Shopify store domain (must end with .myshopify.com)</small>
      <div v-if="error" class="error">{{ error }}</div>
    </div>

    <button @click="handleGenerate" :disabled="!isFormValid">
      Generate Shopify Install Link
    </button>
  </div>
</template>

<script>
const { shell } = require('electron').remote || require('@electron/remote') || require('electron');

export default {
  data() {
    return {
      clientId: '',
      shopDomain: '',
      error: '',
      backendUrl: 'YOUR_BACKEND_URL' // Replace with your actual backend URL
    };
  },
  computed: {
    isFormValid() {
      return this.clientId.trim() && 
             this.shopDomain.trim() && 
             this.shopDomain.endsWith('.myshopify.com');
    }
  },
  methods: {
    validateInputs() {
      if (!this.clientId.trim()) {
        this.error = 'Client ID is required';
        return false;
      }
      if (!this.shopDomain.trim()) {
        this.error = 'Shop domain is required';
        return false;
      }
      if (!this.shopDomain.endsWith('.myshopify.com')) {
        this.error = 'Shop domain must end with .myshopify.com';
        return false;
      }
      this.error = '';
      return true;
    },
    handleGenerate() {
      if (!this.validateInputs()) return;
      
      const oauthUrl = `${this.backendUrl}/shopify/auth?clientId=${encodeURIComponent(this.clientId)}&shop=${encodeURIComponent(this.shopDomain)}`;
      shell.openExternal(oauthUrl);
    }
  }
};
</script>
```

---

## Key Points

1. **Shop Domain Input**: Must be added alongside clientId input
2. **Validation**: Shop domain must end with `.myshopify.com`
3. **Button State**: Disable button until both fields are valid
4. **URL Generation**: Include both `clientId` and `shop` in query string
5. **System Browser**: Use `shell.openExternal()` to open in system browser (not Electron's internal browser)

---

## Testing

After integration, test the flow:

1. Enter a clientId
2. Enter a shop domain (e.g., `mystore.myshopify.com`)
3. Click "Generate Shopify Install Link"
4. Verify the URL opens in your system browser
5. Verify the URL contains both parameters: `?clientId=xxx&shop=xxx.myshopify.com`
6. Complete the OAuth flow and verify backend receives both parameters

---

## Error Handling

If you see "shop query parameter is required" error:
- Check that shop domain input is included in the form
- Verify shop domain validation is working
- Ensure the generated URL includes both `clientId` and `shop` parameters
- Check browser console for any JavaScript errors
