/**
 * Request Decoder - Decode request/response bodies
 * Handles base64, gzip, and other encodings
 */

/**
 * Decode request body from webRequest API
 */
export function decodeRequestBody(requestBody) {
  if (!requestBody || !requestBody.raw) return null;
  
  try {
    const decoder = new TextDecoder('utf-8');
    const decodedParts = requestBody.raw.map(part => {
      if (part.bytes) {
        const byteValues = Object.values(part.bytes);
        return decoder.decode(new Uint8Array(byteValues));
      }
      return '';
    });
    return decodedParts.join('');
  } catch (e) {
    console.error('Hera: Failed to decode request body:', e);
    return '[Hera: Failed to decode body]';
  }
}

/**
 * Decode base64 response body
 */
export function decodeBase64(base64String) {
  try {
    return atob(base64String);
  } catch (e) {
    console.error('Hera: Failed to decode base64:', e);
    return '[Hera: Failed to decode base64]';
  }
}

/**
 * Generate unique session ID
 * SECURITY FIX P1-NEW: Use crypto.randomUUID() instead of Math.random()
 */
export function generateSessionId() {
  return 'session_' + crypto.randomUUID();
}
