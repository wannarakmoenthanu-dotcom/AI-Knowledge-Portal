// =====================================================================
// AI Knowledge & Internal Support Portal - Backend v2 (ขั้นที่ 1: เสริมความปลอดภัย)
// ไฟล์นี้แยกจาก backend/server.js เดิม ไม่ได้เขียนทับของเดิม
// =====================================================================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

// โหลด .env จากโฟลเดอร์แม่ก่อน (ตำแหน่งเดิมของคุณ) แล้วค่อยลองโฟลเดอร์ปัจจุบัน
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });
require('dotenv').config({ quiet: true });

const { GoogleGenAI } = require('@google/genai');

// ---------------------------------------------------------------------
// ค่าตั้งค่า (ปรับได้ผ่าน .env ไม่ต้องแก้โค้ด)
// ---------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
const MAX_QUESTION_LENGTH = Number(process.env.MAX_QUESTION_LENGTH) || 2000;
const AI_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS) || 30000;
const QUESTION_RATE_PER_MIN = Number(process.env.QUESTION_RATE_PER_MIN) || 10;
const API_RATE_PER_15MIN = Number(process.env.API_RATE_PER_15MIN) || 300;

// โดเมนที่อนุญาตให้เรียก API จากเบราว์เซอร์ (คั่นด้วยจุลภาค)
const ALLOWED_ORIGINS = (
    process.env.ALLOWED_ORIGINS ||
    'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5500,http://127.0.0.1:5500'
)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

// คำสั่งระบบ: ลดการเดาเรื่องนโยบายภายในขององค์กร (จนกว่าจะมีระบบค้นเอกสารจริงในขั้นที่ 4-5)
const SYSTEM_PROMPT =
    process.env.SYSTEM_PROMPT ||
    'คุณคือผู้ช่วย AI ของพอร์ทัลความรู้และงานสนับสนุนภายในองค์กร ตอบเป็นภาษาไทยที่สุภาพ กระชับ และเข้าใจง่าย ' +
    'ขณะนี้คุณยังไม่ได้เชื่อมต่อกับเอกสารหรือนโยบายจริงขององค์กร ' +
    'ห้ามยืนยันตัวเลขหรือกฎเกณฑ์เฉพาะขององค์กร (เช่น จำนวนวันลา วงเงินเบิกจ่าย) ราวกับเป็นข้อเท็จจริง ' +
    'ให้ตอบเป็นแนวทางทั่วไปและแนะนำให้ผู้ใช้ตรวจสอบกับฝ่ายที่เกี่ยวข้อง';

// ---------------------------------------------------------------------
// เชื่อมต่อ Gemini (ไม่ให้เซิร์ฟเวอร์ล้มถ้ายังไม่ได้ใส่ key)
// ---------------------------------------------------------------------
const ai = process.env.GEMINI_API_KEY
    ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
    : null;

if (!ai) {
    console.warn('[WARN] ไม่พบ GEMINI_API_KEY - API ถามตอบจะใช้งานไม่ได้จนกว่าจะตั้งค่าใน .env');
}

const app = express();

// ถ้าอยู่หลัง proxy/load balancer (เช่น Render, Cloud Run) ให้ตั้ง TRUST_PROXY=1 เพื่อให้ rate limit เห็น IP จริง
if (process.env.TRUST_PROXY) {
    app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
}

// ---------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------
app.use(
    helmet({
        contentSecurityPolicy: {
            useDefaults: true,
            directives: {
                // หน้า Frontend ปัจจุบันยังมี script/style อยู่ในไฟล์ HTML เดียว จึงต้องเปิด 'unsafe-inline'
                // (ขั้นที่ 8 จะแยกเป็นไฟล์แล้วตัดออกได้)
                'script-src': ["'self'", "'unsafe-inline'"],
                'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
                'font-src': ["'self'", 'https://fonts.gstatic.com'],
                'connect-src': ["'self'"],
                // บังคับ https เฉพาะตอนใช้งานจริง ไม่งั้นทดสอบบน localhost (http) จะมีปัญหา
                'upgrade-insecure-requests': IS_PROD ? [] : null,
            },
        },
    })
);

app.use(
    cors({
        origin(origin, callback) {
            // คำขอที่ไม่มี Origin (same-origin, curl, health check) ให้ผ่าน
            if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
            return callback(null, false);
        },
    })
);

// จำกัดขนาดข้อมูลที่รับเข้ามา
app.use(express.json({ limit: '10kb' }));

// จำกัดจำนวนคำขอ: ทั้งระบบ API และเข้มขึ้นสำหรับ endpoint ที่เรียก AI (ป้องกันการใช้โควตา/ค่าใช้จ่ายจนหมด)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: API_RATE_PER_15MIN,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'มีการเรียกใช้งานถี่เกินไป กรุณาลองใหม่ภายหลัง' },
});

const questionLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: QUESTION_RATE_PER_MIN,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'ถามคำถามถี่เกินไป กรุณารอสักครู่แล้วลองใหม่' },
});

app.use('/api', apiLimiter);

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

// เสิร์ฟหน้าเว็บจากโฟลเดอร์ public (เปิดที่ http://localhost:3000)
app.use(express.static(path.join(__dirname, 'public')));

// ตรวจสถานะระบบ (แทน route "/" เดิมที่ตอบ JSON)
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'AI Knowledge Portal Backend is running!',
        gemini_configured: Boolean(ai),
    });
});


function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function generateWithRetry(question, maxAttempts = 3) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const response = await ai.models.generateContent({
                model: GEMINI_MODEL,
                contents: question,
                config: {
                    systemInstruction: SYSTEM_PROMPT,
                    httpOptions: {
                        timeout: AI_TIMEOUT_MS
                    }
                }
            });

            return response;

        } catch (error) {
            const status = Number(error.status || error.code);
            const retryable =
                status === 429 ||
                status === 503 ||
                status >= 500 ||
                error.code === 'AI_TIMEOUT';

            console.error(
                '[Gemini Error]',
                'Attempt:', attempt,
                'Status:', status || error.code
            );

            if (!retryable || attempt === maxAttempts) {
                throw error;
            }

            const delay = Math.min(2000 * (2 ** (attempt - 1)), 8000);
            await sleep(delay);
        }
    }
}

app.post('/api/questions', questionLimiter, async (req, res) => {
    const question = req.body && req.body.question_text;

    if (typeof question !== 'string' || !question.trim()) {
        return res.status(400).json({ error: 'กรุณากรอกคำถาม' });
    }

    if (question.length > MAX_QUESTION_LENGTH) {
        return res.status(400).json({
            error: `คำถามยาวเกินไป (สูงสุด ${MAX_QUESTION_LENGTH} ตัวอักษร)`
        });
    }

    if (!ai) {
        return res.status(500).json({
            error: 'ระบบ AI ยังไม่ได้ตั้งค่า'
        });
    }

    try {
        const response = await generateWithRetry(question.trim());
        const answer = response.text;

        if (!answer) {
            return res.status(502).json({
                error: 'AI ไม่สามารถสร้างคำตอบได้'
            });
        }

        return res.json({
            status: 'success',
            question_id: crypto.randomUUID(),
            answer_id: crypto.randomUUID(),
            answer_text: answer,
            citations: []
        });

    } catch (error) {
        const status = Number(error.status || error.code);

        if (status === 503 || status === 429 || status >= 500) {
            return res.status(503).json({
                error: 'บริการ AI ไม่พร้อมใช้งานในขณะนี้ กรุณาลองใหม่ภายหลัง'
            });
        }

        if (error.code === 'AI_TIMEOUT') {
            return res.status(504).json({
                error: 'AI ตอบช้าเกินไป กรุณาลองใหม่อีกครั้ง'
            });
        }

        console.error('[Gemini Error]', status || 'UNKNOWN', error.message);

        return res.status(500).json({
            error: 'ไม่สามารถเชื่อมต่อ Gemini AI ได้ กรุณาตรวจสอบการตั้งค่า'
        });
    }
});


// API สำหรับรับคำถามและส่งไปยัง Gemini (path และรูปแบบ JSON เดิม)
app.post('/api/questions', questionLimiter, async (req, res) => {
    const question = req.body && req.body.question_text;

    // ตรวจชนิดและความยาวของข้อมูล
    if (typeof question !== 'string' || !question.trim()) {
        return res.status(400).json({ error: 'กรุณากรอกคำถาม' });
    }
    if (question.length > MAX_QUESTION_LENGTH) {
        return res.status(400).json({
            error: `คำถามยาวเกินไป (สูงสุด ${MAX_QUESTION_LENGTH} ตัวอักษร)`,
        });
    }
    if (!ai) {
        return res.status(500).json({ error: 'ระบบ AI ยังไม่ได้ตั้งค่า กรุณาติดต่อผู้ดูแลระบบ' });
    }

    try {
        const response = await withTimeout(
            ai.models.generateContent({
                model: GEMINI_MODEL,
                contents: question.trim(),
                config: { systemInstruction: SYSTEM_PROMPT },
            }),
            AI_TIMEOUT_MS
        );

        const answer = response.text;

        res.json({
            status: 'success',
            question_id: crypto.randomUUID(),
            answer_id: crypto.randomUUID(),
            answer_text: answer || 'AI ไม่สามารถสร้างคำตอบได้',
            citations: [],
        });
    } catch (error) {
        // บันทึกเฉพาะข้อมูลที่จำเป็น ไม่ log ตัวคำถามหรือ object ข้อผิดพลาดทั้งก้อน
        console.error('[Gemini Error]', error.code || error.status || '', error.message);

        if (error.code === 'AI_TIMEOUT') {
            return res.status(504).json({ error: 'AI ตอบช้าเกินไป กรุณาลองใหม่อีกครั้ง' });
        }
        res.status(500).json({ error: 'ไม่สามารถเชื่อมต่อ Gemini AI ได้ กรุณาลองใหม่' });
    }
});

// ---------------------------------------------------------------------
// Error handlers
// ---------------------------------------------------------------------
app.use('/api', (req, res) => {
    res.status(404).json({ error: 'ไม่พบ API ที่เรียก' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    // JSON ที่ส่งมาผิดรูปแบบ หรือใหญ่เกินกำหนด
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'รูปแบบข้อมูลไม่ถูกต้อง' });
    }
    if (err.type === 'entity.too.large') {
        return res.status(413).json({ error: 'ข้อมูลที่ส่งมามีขนาดใหญ่เกินไป' });
    }
    console.error('[Server Error]', err.message);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดภายในระบบ' });
});

// ---------------------------------------------------------------------
// เปิด Server + ปิดอย่างเรียบร้อย
// ---------------------------------------------------------------------
const server = app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Model: ${GEMINI_MODEL} | Environment: ${IS_PROD ? 'production' : 'development'}`);
});

function shutdown(signal) {
    console.log(`${signal} received, shutting down...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
