
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3000;

// ตั้งค่าพื้นฐาน
app.use(cors());
app.use(express.json());

// ทดสอบ Backend
app.get('/', (req, res) => {
    res.json({
        message: 'AI Knowledge Portal Backend is running!'
    });
});

// API สำหรับรับคำถาม
app.post('/api/questions', (req, res) => {
    const { question_text } = req.body;

    if (!question_text || !question_text.trim()) {
        return res.status(400).json({
            error: 'กรุณากรอกคำถาม'
        });
    }

    res.json({
        status: 'success',
        question_id: 1,
        answer_id: 1,
        answer_text: 'Backend ได้รับคำถามแล้ว: ' + question_text,
        citations: []
    });
});

// เปิด Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
