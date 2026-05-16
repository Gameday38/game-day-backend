const express = require(‘express’);
const cors = require(‘cors’);
const paypal = require(’@paypal/checkout-server-sdk’);
const app = express();
const PORT = process.env.PORT || 3001;
const clientId = process.env.PAYPAL_CLIENT_ID;
const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
const payPalMode = process.env.PAYPAL_MODE || ‘sandbox’;
const environment = payPalMode === ‘live’
? new paypal.core.LiveEnvironment(clientId, clientSecret)
: new paypal.core.SandboxEnvironment(clientId, clientSecret);
const paypalClient = new paypal.core.PayPalHttpClient(environment);
app.use(cors({ origin: ‘*’ }));
app.use(express.json());
app.get(’/health’, (req, res) => res.json({ status: ‘ok’ }));
app.post(’/api/create-order’, async (req, res) => {
try {
const { planType, isYearly } = req.body;
const prices = {
premium: { monthly: ‘9.99’, yearly: ‘99.99’ },
pro: { monthly: ‘19.99’, yearly: ‘199.99’ }
};
const price = prices[planType]?.[isYearly ? ‘yearly’ : ‘monthly’];

const request = new paypal.orders.OrdersCreateRequest();
request.requestBody({
  intent: 'CAPTURE',
  purchase_units: [{ amount: { currency_code: 'USD', value: price }}]
});

const order = await paypalClient.execute(request);
res.json({ orderId: order.result.id, amount: price });


} catch (error) {
res.status(500).json({ error: error.message });
}
});
app.post(’/api/capture-order’, async (req, res) => {
try {
const { orderId } = req.body;
const request = new paypal.orders.OrdersCaptureRequest(orderId);
const capture = await paypalClient.execute(request);
res.json({ status: capture.result.status });
} catch (error) {
res.status(500).json({ error: error.message });
}
});
app.listen(PORT, ‘0.0.0.0’, () => {
console.log(Server running on port ${PORT});
});
