/**
 * Analytics Dashboard JavaScript
 * Handles chart initialization and data visualization
 */

let monthlyChart = null;
let typeChart = null;
let topDocsChart = null;

// Chart configuration
const chartConfig = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            position: 'top',
        },
        tooltip: {
            mode: 'index',
            intersect: false,
        }
    },
    scales: {
        x: {
            display: true,
            title: {
                display: true
            }
        },
        y: {
            display: true,
            title: {
                display: true
            }
        }
    }
};

// Color schemes
const colors = {
    primary: '#0d6efd',
    secondary: '#6c757d',
    success: '#198754',
    info: '#0dcaf0',
    warning: '#ffc107',
    danger: '#dc3545',
    light: '#f8f9fa',
    dark: '#212529'
};

const chartColors = [
    colors.primary,
    colors.success,
    colors.warning,
    colors.info,
    colors.danger,
    colors.secondary
];

// Initialize all charts
function initializeCharts() {
    initializeMonthlyChart();
    initializeTypeChart();
    initializeTopDocsChart();
    
    // Add resize handler
    window.addEventListener('resize', handleResize);
}

function initializeMonthlyChart() {
    const ctx = document.getElementById('monthlyChart');
    if (!ctx) return;
    
    // Fetch data for monthly chart
    fetchChartData('monthly_requests')
        .then(data => {
            monthlyChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Document Requests',
                        data: data.data,
                        borderColor: colors.primary,
                        backgroundColor: `${colors.primary}20`,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: colors.primary,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    ...chartConfig,
                    scales: {
                        ...chartConfig.scales,
                        x: {
                            ...chartConfig.scales.x,
                            title: {
                                display: true,
                                text: 'Month'
                            }
                        },
                        y: {
                            ...chartConfig.scales.y,
                            title: {
                                display: true,
                                text: 'Number of Requests'
                            },
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        ...chartConfig.plugins,
                        tooltip: {
                            callbacks: {
                                title: function(context) {
                                    return `Month: ${context[0].label}`;
                                },
                                label: function(context) {
                                    return `Requests: ${context.parsed.y}`;
                                }
                            }
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error loading monthly chart:', error);
            showChartError(ctx, 'Failed to load monthly data');
        });
}

function initializeTypeChart() {
    const ctx = document.getElementById('typeChart');
    if (!ctx) return;
    
    // Fetch data for document types chart
    fetchChartData('document_types')
        .then(data => {
            typeChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: data.labels,
                    datasets: [{
                        data: data.data,
                        backgroundColor: chartColors.slice(0, data.labels.length),
                        borderColor: '#fff',
                        borderWidth: 2,
                        hoverBorderWidth: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((context.parsed / total) * 100).toFixed(1);
                                    return `${context.label}: ${context.parsed} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error loading type chart:', error);
            showChartError(ctx, 'Failed to load document type data');
        });
}

function initializeTopDocsChart() {
    const ctx = document.getElementById('topDocsChart');
    if (!ctx) return;
    
    // Fetch data for top documents chart
    fetchChartData('top_documents')
        .then(data => {
            topDocsChart = new Chart(ctx, {
                type: 'horizontalBar',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Access Count',
                        data: data.data,
                        backgroundColor: colors.info,
                        borderColor: colors.info,
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                title: function(context) {
                                    return context[0].label;
                                },
                                label: function(context) {
                                    return `Accessed: ${context.parsed.x} times`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Access Count'
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: 'Documents'
                            }
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error loading top documents chart:', error);
            showChartError(ctx, 'Failed to load top documents data');
        });
}

async function fetchChartData(chartType) {
    try {
        const response = await fetch(`/api/analytics/chart_data?type=${chartType}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`Error fetching ${chartType} data:`, error);
        throw error;
    }
}

function showChartError(ctx, message) {
    const parent = ctx.parentElement;
    parent.innerHTML = `
        <div class="d-flex align-items-center justify-content-center h-100">
            <div class="text-center text-muted">
                <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                <p>${message}</p>
                <button class="btn btn-sm btn-outline-primary" onclick="location.reload()">
                    <i class="fas fa-refresh me-1"></i>Retry
                </button>
            </div>
        </div>
    `;
}

function handleResize() {
    // Resize charts when window is resized
    if (monthlyChart) monthlyChart.resize();
    if (typeChart) typeChart.resize();
    if (topDocsChart) topDocsChart.resize();
}

// Export chart as image
function exportChart(chartInstance, filename) {
    if (!chartInstance) return;
    
    const link = document.createElement('a');
    link.download = `${filename}.png`;
    link.href = chartInstance.toBase64Image();
    link.click();
}

// Refresh chart data
function refreshChartData() {
    // Show loading state
    showLoadingState();
    
    // Destroy existing charts
    if (monthlyChart) {
        monthlyChart.destroy();
        monthlyChart = null;
    }
    if (typeChart) {
        typeChart.destroy();
        typeChart = null;
    }
    if (topDocsChart) {
        topDocsChart.destroy();
        topDocsChart = null;
    }
    
    // Reinitialize charts
    setTimeout(() => {
        initializeCharts();
        hideLoadingState();
    }, 500);
}

function showLoadingState() {
    const charts = ['monthlyChart', 'typeChart', 'topDocsChart'];
    charts.forEach(chartId => {
        const ctx = document.getElementById(chartId);
        if (ctx) {
            const parent = ctx.parentElement;
            parent.innerHTML = `
                <div class="d-flex align-items-center justify-content-center h-100">
                    <div class="text-center">
                        <div class="spinner-border text-primary mb-2" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="text-muted">Loading chart data...</p>
                    </div>
                </div>
            `;
        }
    });
}

function hideLoadingState() {
    // Charts will be recreated with new canvases
}

// Real-time updates (if WebSocket is available)
function setupRealTimeUpdates() {
    // This would be implemented if real-time updates are needed
    // using WebSocket or Server-Sent Events
    
    // Example:
    // const eventSource = new EventSource('/analytics/updates');
    // eventSource.onmessage = function(event) {
    //     const data = JSON.parse(event.data);
    //     updateChartData(data);
    // };
}

// Update chart data without full refresh
function updateChartData(newData) {
    if (monthlyChart && newData.monthly) {
        monthlyChart.data.labels = newData.monthly.labels;
        monthlyChart.data.datasets[0].data = newData.monthly.data;
        monthlyChart.update('none'); // No animation for real-time updates
    }
    
    if (typeChart && newData.types) {
        typeChart.data.labels = newData.types.labels;
        typeChart.data.datasets[0].data = newData.types.data;
        typeChart.update('none');
    }
    
    if (topDocsChart && newData.topDocs) {
        topDocsChart.data.labels = newData.topDocs.labels;
        topDocsChart.data.datasets[0].data = newData.topDocs.data;
        topDocsChart.update('none');
    }
}

// Keyboard shortcuts for analytics
document.addEventListener('keydown', function(event) {
    // R key to refresh data
    if (event.key === 'r' && event.ctrlKey) {
        event.preventDefault();
        refreshChartData();
    }
    
    // E key to export current view
    if (event.key === 'e' && event.ctrlKey) {
        event.preventDefault();
        exportAnalytics();
    }
});

function exportAnalytics() {
    // Export all charts and data
    alert('Export functionality would generate a comprehensive report with all charts and statistics');
}

// Cleanup when page unloads
window.addEventListener('beforeunload', function() {
    if (monthlyChart) monthlyChart.destroy();
    if (typeChart) typeChart.destroy();
    if (topDocsChart) topDocsChart.destroy();
});

// Touch gestures for mobile
let touchStartX = 0;
let touchStartY = 0;

document.addEventListener('touchstart', function(event) {
    touchStartX = event.touches[0].clientX;
    touchStartY = event.touches[0].clientY;
});

document.addEventListener('touchend', function(event) {
    const touchEndX = event.changedTouches[0].clientX;
    const touchEndY = event.changedTouches[0].clientY;
    
    const deltaX = touchEndX - touchStartX;
    const deltaY = touchEndY - touchStartY;
    
    // Swipe down to refresh
    if (deltaY > 50 && Math.abs(deltaX) < 100) {
        refreshChartData();
    }
});
