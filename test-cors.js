const axios = require('axios');

const testCors = async () => {
  const baseUrl = 'https://smcback-production-6d12.up.railway.app';
  const testOrigin = 'https://smcscout.netlify.app';
  
  console.log('🧪 Testing CORS configuration...');
  console.log(`📍 Backend URL: ${baseUrl}`);
  console.log(`🌐 Test Origin: ${testOrigin}`);
  
  try {
    // Test 1: Simple GET request
    console.log('\n1️⃣ Testing simple GET request...');
    const response1 = await axios.get(`${baseUrl}/cors-test`, {
      headers: {
        'Origin': testOrigin
      }
    });
    console.log('✅ GET request successful:', response1.data);
    
    // Test 2: OPTIONS preflight request
    console.log('\n2️⃣ Testing OPTIONS preflight request...');
    const response2 = await axios.options(`${baseUrl}/cors-test`, {
      headers: {
        'Origin': testOrigin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type'
      }
    });
    console.log('✅ OPTIONS request successful');
    console.log('CORS Headers:', {
      'Access-Control-Allow-Origin': response2.headers['access-control-allow-origin'],
      'Access-Control-Allow-Credentials': response2.headers['access-control-allow-credentials'],
      'Access-Control-Allow-Methods': response2.headers['access-control-allow-methods'],
      'Access-Control-Allow-Headers': response2.headers['access-control-allow-headers']
    });
    
    // Test 3: POST request with preflight
    console.log('\n3️⃣ Testing POST request (should trigger preflight)...');
    const response3 = await axios.post(`${baseUrl}/api/public-test`, {
      test: 'data'
    }, {
      headers: {
        'Origin': testOrigin,
        'Content-Type': 'application/json'
      }
    });
    console.log('✅ POST request successful:', response3.data);
    
  } catch (error) {
    console.error('❌ CORS test failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response headers:', error.response.headers);
      console.error('Response data:', error.response.data);
    }
  }
};

// Run the test
testCors();
