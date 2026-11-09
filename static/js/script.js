const dropZone = document.getElementById("dropZone");
const qrImage = document.getElementById("qrImage");
const preview = document.getElementById("preview");
const scanForm = document.getElementById("scanForm");
const scanButton = document.getElementById("scanButton");

function showPreview(file) {
    if (!file || !file.type.startsWith("image/")) return;

    const reader = new FileReader();
    reader.onload = function (event) {
        preview.innerHTML = `<img src="${event.target.result}" alt="QR preview">`;
        preview.style.display = "block";
    };
    reader.readAsDataURL(file);
}

if (qrImage) {
    qrImage.addEventListener("change", function () {
        showPreview(this.files[0]);
    });
}

if (dropZone) {
    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, function (event) {
            event.preventDefault();
            dropZone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, function (event) {
            event.preventDefault();
            dropZone.classList.remove("dragover");
        });
    });

    dropZone.addEventListener("drop", function (event) {
        const file = event.dataTransfer.files[0];
        if (file) {
            try {
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(file);
                qrImage.files = dataTransfer.files;
            } catch (error) {
                console.log("File assignment not supported.");
            }
            showPreview(file);
        }
    });
}

if (scanForm) {
    scanForm.addEventListener("submit", function () {
        scanButton.disabled = true;
        scanButton.innerHTML = "<span>Analyzing...</span><span class='arrow'>↻</span>";
    });
}

const result = document.getElementById("result");
if (result) {
    setTimeout(() => {
        result.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 150);
}

// Animate the risk-score ring and the number it surrounds.
const scoreRing = document.querySelector(".ring-fill");
const scoreValue = document.querySelector(".score-value");

if (scoreRing && scoreValue) {
    const target = parseInt(scoreRing.dataset.score, 10) || 0;
    const radius = scoreRing.getAttribute("r");
    const circumference = 2 * Math.PI * radius;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    scoreRing.style.strokeDasharray = `${circumference}`;
    scoreRing.style.strokeDashoffset = `${circumference}`;
    const targetOffset = circumference - (circumference * target) / 100;

    if (reduceMotion) {
        scoreRing.style.strokeDashoffset = `${targetOffset}`;
        scoreValue.textContent = target;
    } else {
        requestAnimationFrame(() => {
            scoreRing.style.strokeDashoffset = `${targetOffset}`;
        });

        const duration = 900;
        const start = performance.now();

        function tick(now) {
            const progress = Math.min((now - start) / duration, 1);
            scoreValue.textContent = Math.round(progress * target);
            if (progress < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
    }
}
