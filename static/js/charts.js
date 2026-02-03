const canvas = document.getElementById('attackChart');
const placeholder = document.getElementById('chartPlaceholder');

if (!counts || counts.length === 0) {
    if (placeholder) placeholder.style.display = 'flex';
} else {
    if (placeholder) placeholder.style.display = 'none';
    const ctx = canvas.getContext('2d');

    new Chart(ctx, {
        type: 'pie', // Normal Pie Chart
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: [
                    '#38bdf8', // Light Blue (IDS)
                    '#2dd4bf', // Teal (Phish)
                    '#f43f5e', // Rose (Danger)
                    '#fbbf24', // Amber
                    '#818cf8', // Indigo
                    '#c084fc', // Purple
                    '#94a3b8'  // Slate
                ],
                borderColor: '#020617',
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        usePointStyle: true,
                        padding: 20,
                        font: { family: 'Inter', size: 12 }
                    }
                },
                tooltip: {
                    backgroundColor: '#1e293b',
                    padding: 12,
                    cornerRadius: 8,
                    titleFont: { family: 'Inter', size: 13 },
                    bodyFont: { family: 'Inter', size: 12 }
                }
            }
        }
    });
}
