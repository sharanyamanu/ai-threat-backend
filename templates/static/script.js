const ctx = document.getElementById('chart');

const chartData = window.chartData || [0,0,0];

if (ctx) {
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Late Login','Failed Attempts','High File Access'],
            datasets: [{
                label: 'Threat Indicators',
                data: chartData,
                backgroundColor: ['red','orange','yellow']
            }]
        }
    });
}