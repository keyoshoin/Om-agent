/**
 * NSFOCUS O&M Agent — Vue 3 SPA
 *
 * CDN 依赖: Vue 3, Element Plus, Axios, marked
 */

const { createApp, ref, reactive, computed, watch, onMounted, onUnmounted, nextTick } = Vue;

// ─── API 基础 ────────────────────────────────────────────────────────────────

const api = axios.create({ baseURL: '' });

// ─── API Key 管理 ─────────────────────────────────────────────────────────────

// 从 sessionStorage 读取已保存的 API Key (仅当前标签页有效)
let savedApiKey = '';
try {
    savedApiKey = sessionStorage.getItem('om_agent_api_key') || '';
} catch {}

// 设置 axios 拦截器，自动附加 X-API-Key 请求头
api.interceptors.request.use(config => {
    const key = savedApiKey || (() => {
        try { return sessionStorage.getItem('om_agent_api_key') || ''; } catch { return ''; }
    })();
    if (key) {
        config.headers['X-API-Key'] = key;
    }
    return config;
});

// 处理 401 响应，提示用户重新输入 API Key
api.interceptors.response.use(
    resp => resp,
    error => {
        if (error.response?.status === 401) {
            try { sessionStorage.removeItem('om_agent_api_key'); } catch {}
            savedApiKey = '';
            // 触发全局事件，让 App 组件显示 API Key 输入弹窗
            window.dispatchEvent(new CustomEvent('auth-required'));
        }
        return Promise.reject(error);
    }
);

// ─── 设备管理组件 ────────────────────────────────────────────────────────────

const DevicesPage = {
    template: `
    <div>
        <div class="page-header">
            <h3>设备管理</h3>
            <el-button type="primary" @click="showAddDialog">+ 添加设备</el-button>
        </div>
        <el-table :data="devices" stripe v-loading="loading" empty-text="暂无设备">
            <el-table-column prop="name" label="设备名称" min-width="140" />
            <el-table-column prop="host" label="IP 地址" width="160" />
            <el-table-column prop="port" label="端口" width="80" />
            <el-table-column prop="username" label="用户" width="100" />
            <el-table-column label="密码" width="90">
                <template #default="scope">
                    <span v-if="scope.row.has_password" style="color:#67c23a">已保存</span>
                    <span v-else style="color:#909399">未设置</span>
                </template>
            </el-table-column>
            <el-table-column label="操作" width="320">
                <template #default="scope">
                    <el-button size="small" @click="editDevice(scope.row)">编辑</el-button>
                    <el-button size="small" type="success" @click="$emit('select-device', scope.row)">选用</el-button>
                    <el-button size="small" type="danger" @click="deleteDevice(scope.row.id)">删除</el-button>
                </template>
            </el-table-column>
        </el-table>

        <!-- 添加/编辑弹窗 -->
        <el-dialog :title="editing ? '编辑设备' : '添加设备'" v-model="dialogVisible" width="520px">
            <el-form :model="form" label-width="100px">
                <el-form-item label="设备名称">
                    <el-input v-model="form.name" placeholder="如: 核心防火墙-1" />
                </el-form-item>
                <el-form-item label="IP 地址">
                    <el-input v-model="form.host" placeholder="192.168.1.100" />
                </el-form-item>
                <el-form-item label="SSH 端口">
                    <el-input-number v-model="form.port" :min="1" :max="65535" />
                </el-form-item>
                <el-form-item label="用户名">
                    <el-input v-model="form.username" placeholder="admin" />
                </el-form-item>
                <el-form-item label="SSH 密码">
                    <el-input v-model="form.password" type="password" show-password
                        :placeholder="editing ? '留空则不修改已保存的密码' : '留空则不保存密码'" />
                    <span v-if="editing && form._has_saved_password" style="font-size:12px;color:#67c23a;margin-top:4px;display:inline-block">
                        ⚠ 设备当前已有存储密码，留空可保留原密码，输入新密码将覆盖
                    </span>
                </el-form-item>
            </el-form>
            <template #footer>
                <el-button @click="dialogVisible = false">取消</el-button>
                <el-button type="primary" @click="saveDevice">{{ editing ? '保存' : '添加' }}</el-button>
            </template>
        </el-dialog>

    </div>`,

    emits: ['select-device'],

    setup() {
        const devices = ref([]);
        const loading = ref(false);
        const dialogVisible = ref(false);
        const editing = ref(false);
        const editId = ref(null);
        const form = reactive({ name: '', host: '', port: 22, username: '', password: '', _has_saved_password: false });
        async function fetchDevices() {
            loading.value = true;
            try {
                const { data } = await api.get('/api/devices');
                devices.value = data;
            } finally {
                loading.value = false;
            }
        }

        function showAddDialog() {
            editing.value = false;
            editId.value = null;
            form.name = ''; form.host = ''; form.port = 22; form.username = ''; form.password = ''; form._has_saved_password = false;
            dialogVisible.value = true;
        }

        function editDevice(row) {
            editing.value = true;
            editId.value = row.id;
            form.name = row.name; form.host = row.host;
            form.port = row.port; form.username = row.username; form.password = '';
            form._has_saved_password = !!row.has_password;
            dialogVisible.value = true;
        }

        async function saveDevice() {
            try {
                if (editing.value) {
                    const payload = { name: form.name, host: form.host, port: form.port, username: form.username };
                    if (form.password) payload.password = form.password;
                    await api.put(`/api/devices/${editId.value}`, payload);
                } else {
                    await api.post('/api/devices', { ...form });
                }
                dialogVisible.value = false;
                await fetchDevices();
                ElementPlus.ElMessage.success(editing.value ? '设备已更新' : '设备已添加');
            } catch (e) {
                ElementPlus.ElMessage.error('保存失败: ' + (e.response?.data?.detail || e.message));
            }
        }

        async function deleteDevice(id) {
            try {
                await ElementPlus.ElMessageBox.confirm('确定删除该设备？相关运行记录不会被删除。', '确认');
                await api.delete(`/api/devices/${id}`);
                await fetchDevices();
                ElementPlus.ElMessage.success('设备已删除');
            } catch (e) {
                if (e !== 'cancel') ElementPlus.ElMessage.error('删除失败');
            }
        }

        onMounted(() => {
            fetchDevices();
        });

        onUnmounted(() => {});
        return {
            devices, loading, dialogVisible, editing, form,
            showAddDialog, editDevice, saveDevice, deleteDevice,
        };
    }
};

// ─── 执行任务组件 ────────────────────────────────────────────────────────────

const ExecutePage = {
    template: `
    <div style="display:flex; flex-direction:column; align-items:center">
        <div class="page-header" style="width:100%; max-width:700px"><h3>执行任务</h3></div>
        <el-card style="width:100%; max-width:700px">
            <el-form label-width="100px">
                <el-form-item label="目标设备">
                    <el-select v-model="host" filterable placeholder="选择设备或手动输入 IP" style="width:100%"
                        @change="onDeviceSelect">
                        <el-option v-for="d in devices" :key="d.id"
                            :label="d.name + ' (' + d.host + ')'" :value="d.host" />
                    </el-select>
                </el-form-item>
                <el-form-item label="IP 地址">
                    <el-input v-model="host" placeholder="也可直接输入 IP" />
                </el-form-item>
                <el-form-item label="SSH 端口">
                    <el-input-number v-model="port" :min="1" :max="65535" />
                </el-form-item>
                <el-form-item label="用户名">
                    <el-input v-model="username" placeholder="SSH 用户名" />
                </el-form-item>
                <el-form-item label="密码">
                    <el-input v-model="password" type="password" show-password
                        placeholder="SSH 密码 (选择设备后自动填充)">
                        <template #suffix>
                            <span v-if="passwordFromDevice" style="font-size:12px;color:#67c23a;line-height:32px">
                                已自动填充
                            </span>
                        </template>
                    </el-input>
                </el-form-item>
                <el-divider />
                <el-form-item label="工作流类型">
                    <el-radio-group v-model="workflowType">
                        <el-radio value="full_link">全链路巡检</el-radio>
                        <el-radio value="targeted">针对性排查</el-radio>
                    </el-radio-group>
                </el-form-item>
                <el-form-item v-if="workflowType === 'targeted'" label="故障描述">
                    <el-input v-model="errorInput" type="textarea" :rows="3"
                        placeholder="描述故障现象，如: Web 管理界面打不开，返回 502" />
                </el-form-item>

                <!-- 文件上传 (仅针对性排查) -->
                <el-form-item v-if="workflowType === 'targeted'" label="上传附件">
                    <div class="upload-zone"
                        @dragover.prevent="dragOver = true"
                        @dragleave.prevent="dragOver = false"
                        @drop.prevent="onDrop"
                        :class="{ 'drag-over': dragOver }"
                        @click="triggerFileInput">
                        <input type="file" ref="fileInput" multiple
                            accept="image/*,.txt,.log,.xml,.conf,.json,.csv"
                            @change="onFileChange" style="display:none" />
                        <div v-if="uploadedFiles.length === 0" class="upload-placeholder">
                            <div class="upload-icon">📎</div>
                            <div>拖拽文件到此处，或点击选择</div>
                            <div style="font-size:12px;color:#909399;margin-top:4px">
                                支持图片 (PNG/JPG) / 日志 (.txt/.log) / 配置 (.xml/.conf)
                            </div>
                        </div>
                    </div>
                    <!-- 已选文件列表 -->
                    <div v-if="uploadedFiles.length > 0" class="file-list">
                        <div v-for="(f, idx) in uploadedFiles" :key="idx" class="file-item">
                            <span class="file-icon">{{ f.isImage ? '🖼' : '📄' }}</span>
                            <span class="file-name">{{ f.name }}</span>
                            <span class="file-size">{{ formatSize(f.size) }}</span>
                            <el-button type="danger" size="small" circle @click="removeFile(idx)">✕</el-button>
                        </div>
                        <div class="upload-zone upload-zone-sm"
                            @dragover.prevent="dragOver = true"
                            @dragleave.prevent="dragOver = false"
                            @drop.prevent="onDrop"
                            :class="{ 'drag-over': dragOver }"
                            @click="triggerFileInput">
                            <span style="color:#409eff;cursor:pointer">+ 添加更多文件</span>
                        </div>
                    </div>
                    <!-- 图片预览 -->
                    <div v-if="imagePreviews.length > 0" class="image-previews">
                        <div v-for="(preview, idx) in imagePreviews" :key="idx" class="image-preview-item">
                            <img :src="preview.dataUrl" :alt="preview.name"
                                @click="showFullImage(preview.dataUrl)" />
                            <div class="image-preview-name">{{ preview.name }}</div>
                        </div>
                    </div>
                </el-form-item>

                <el-form-item>
                    <el-button type="primary" size="large" @click="startTask"
                        :loading="running" :disabled="!canStart">
                        {{ running ? '执行中...' : '▶ 开始执行' }}
                    </el-button>
                    <span v-if="uploadedFiles.length > 0" style="margin-left:12px;color:#909399">
                        已选择 {{ uploadedFiles.length }} 个文件
                    </span>
                </el-form-item>
            </el-form>
        </el-card>

        <!-- 图片大图预览弹窗 -->
        <el-dialog v-model="fullImageVisible" title="图片预览" width="80%">
            <img :src="fullImageSrc" style="width:100%" />
        </el-dialog>

        <!-- 执行进度 (任务启动后显示) -->
        <div v-if="showProgress" style="width:100%; max-width:700px; margin-top:20px">
            <div class="page-header">
                <h3>执行进度</h3>
                <div>
                    <el-tag :type="wsConnected ? 'success' : 'danger'" size="small" style="margin-right:8px">
                        {{ wsConnected ? '已连接' : '断开' }}
                    </el-tag>
                    <el-tag v-if="totalSteps > 0" type="info" size="small">{{ currentStep }} / {{ totalSteps }}</el-tag>
                </div>
            </div>

            <!-- 进度条 -->
            <div v-if="totalSteps > 0" style="margin-bottom:16px">
                <el-progress :percentage="Math.round(currentStep/totalSteps*100)"
                    :status="finished ? 'success' : undefined"
                    :text-inside="true" :stroke-width="20" />
            </div>

            <!-- 层状态卡片 (仅全链路) -->
            <el-row v-if="runningWorkflow === 'full_link'" :gutter="12" style="margin-bottom:16px">
                <el-col :span="6" v-for="layer in layers" :key="layer.key">
                    <el-card shadow="hover" class="layer-status-card"
                        :class="'layer-' + layer.status">
                        <div style="text-align:center">
                            <div style="font-size:22px">
                                {{ {pending:'⏳',running:'🔄',ok:'✅',warning:'⚠️',error:'❌'}[layer.status] || '⏳' }}
                            </div>
                            <div style="font-weight:bold;font-size:13px;margin:4px 0">{{ layer.label }}</div>
                            <div v-if="layer.status === 'ok' || layer.status === 'warning' || layer.status === 'error'"
                                style="font-size:11px;color:#909399">
                                {{ layer.passed }}/{{ layer.total }} 通过
                            </div>
                            <div v-else style="font-size:11px;color:#909399">
                                {{ {pending:'等待中',running:'执行中...'}[layer.status] }}
                            </div>
                        </div>
                    </el-card>
                </el-col>
            </el-row>

            <!-- 执行日志 -->
            <el-card>
                <div class="monitor-log" ref="logContainer">
                    <div v-for="(entry, idx) in logEntries" :key="idx" class="log-entry"
                        :class="'log-' + entry.type">
                        <span class="log-time">{{ entry.time }}</span>
                        <span class="log-icon">{{ entry.icon || '•' }}</span>
                        <span class="log-msg" v-html="entry.message"></span>
                    </div>
                </div>
            </el-card>

            <!-- 最终报告 (任务完成后显示) -->
            <div v-if="finished && finalReport" style="width:100%; max-width:700px; margin-top:20px">
                <div class="page-header">
                    <h3>📄 巡检报告</h3>
                    <el-button size="small" @click="copyReport">复制</el-button>
                    <el-button size="small" @click="exportReport">导出文件</el-button>
                </div>
                <el-card>
                    <div class="markdown-body" v-html="renderedReport"></div>
                </el-card>
            </div>
        </div>
    </div>`,

    props: { preselectedDevice: Object },

    setup(props) {
        const devices = ref([]);
        const host = ref('');
        const port = ref(22);
        const username = ref('root');
        const password = ref('');
        const passwordFromDevice = ref(false);
        const selectedDeviceId = ref(0);
        const workflowType = ref('full_link');
        const errorInput = ref('');
        const running = ref(false);
        const canStart = computed(() => host.value && username.value && password.value);

        // 文件上传
        const fileInput = ref(null);
        const dragOver = ref(false);
        const uploadedFiles = ref([]);         // {name, size, isImage, file: File, dataUrl?}
        const imagePreviews = computed(() =>
            uploadedFiles.value.filter(f => f.isImage && f.dataUrl)
        );
        const fullImageVisible = ref(false);
        const fullImageSrc = ref('');

        // 进度显示
        const showProgress = ref(false);
        const wsConnected = ref(false);
        const finalReport = ref('');
        const renderedReport = computed(() => {
            if (!finalReport.value) return '';
            try {
                if (typeof marked !== 'undefined' && marked.parse) {
                    return marked.parse(finalReport.value);
                }
                // marked 未加载时，手动把换行转 <br>，表头/分隔线保留
                return finalReport.value.replace(/\n/g, '<br>');
            } catch { return finalReport.value.replace(/\n/g, '<br>'); }
        });
        const finished = ref(false);
        const currentStep = ref(0);
        const totalSteps = ref(0);
        const logEntries = ref([]);
        let ws = null;
        let sessionId = '';

        const layers = reactive([
            { key: 'web',    label: 'Web 层',    status: 'pending', passed: 0, total: 0 },
            { key: 'python', label: 'Python 层', status: 'pending', passed: 0, total: 0 },
            { key: 'engine', label: '引擎层',    status: 'pending', passed: 0, total: 0 },
            { key: 'system', label: '系统层',    status: 'pending', passed: 0, total: 0 },
        ]);

        function resetProgress() {
            showProgress.value = true;
            finished.value = false;
            currentStep.value = 0;
            totalSteps.value = 0;
            logEntries.value = [];
            layers.forEach(l => { l.status = 'pending'; l.passed = 0; l.total = 0; });
        }

        function addLog(type, msg, icon) {
            logEntries.value.push({
                time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
                type, message: msg, icon: icon || '',
            });
            if (logEntries.value.length > 500) logEntries.value.shift();
            nextTick(() => {
                const el = document.querySelector('.monitor-log');
                if (el) el.scrollTop = el.scrollHeight;
            });
        }

        function connectWS(sid) {
            return new Promise((resolve) => {
                sessionId = sid;
                const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
                const token = savedApiKey || (() => {
                    try { return sessionStorage.getItem('om_agent_api_key') || ''; } catch { return ''; }
                })();
                const url = `${proto}//${location.host}/ws/stream/${sid}?token=${encodeURIComponent(token)}`;
                ws = new WebSocket(url);
                ws.onopen = () => {
                    wsConnected.value = true;
                    addLog('info', '已连接到实时数据流', '🔌');
                    resolve();
                };
                ws.onmessage = (e) => {
                    try { handleWSEvent(JSON.parse(e.data)); }
                    catch { addLog('info', e.data, '📨'); }
                };
                ws.onclose = () => { wsConnected.value = false; addLog('info', '数据流已断开', '🔌'); };
                ws.onerror = () => {
                    wsConnected.value = false;
                    addLog('error', 'WebSocket 连接错误', '❌');
                    resolve(); // 即使失败也继续，不阻塞
                };
                // 超时保护：2秒没连上也继续
                setTimeout(() => resolve(), 2000);
            });
        }

        function disconnectWS() {
            if (ws) { ws.close(); ws = null; }
        }

        const runningWorkflow = ref('');  // 当前运行的工作流类型

        function handleWSEvent(d) {
            switch (d.type) {
                case 'workflow_start':
                    runningWorkflow.value = d.workflow_type || '';
                    if (runningWorkflow.value === 'full_link') {
                        totalSteps.value = 4;
                        layers.forEach(l => l.status = 'pending');
                    } else {
                        totalSteps.value = 0;  // targeted 无固定步骤
                    }
                    addLog('success', `任务开始执行 (${runningWorkflow.value === 'full_link' ? '全链路巡检' : '针对性排查'})`, '🚀');
                    break;
                case 'ssh_connected':
                    if (d.status === 'ok') addLog('success', `SSH 已连接: ${d.host}`, '🔗');
                    else { addLog('error', `SSH 连接失败: ${d.error || ''}`, '🔗'); finished.value = true; }
                    break;
                case 'layer_start': {
                    if (runningWorkflow.value === 'full_link') {
                        const layer = layers.find(l => l.key === d.layer);
                        if (layer) { layer.status = 'running'; layer.total = 0; }
                    }
                    addLog('info', `开始检查 <b>${d.layer.toUpperCase()}</b> 层...`, '🔍');
                    break;
                }
                case 'layer_done': {
                    if (runningWorkflow.value === 'full_link') {
                        const layer = layers.find(l => l.key === d.layer);
                        if (layer) { layer.status = d.status; layer.passed = d.passed; layer.total = d.total; }
                        currentStep.value++;
                    }
                    const icon = d.errors > 0 ? '❌' : (d.warnings > 0 ? '⚠️' : '✅');
                    addLog(d.status === 'error' ? 'error' : (d.status === 'warning' ? 'warning' : 'success'),
                        `${(d.layer || '').toUpperCase()} 层完成: <b>${d.passed}/${d.total}</b> 通过` +
                        (d.warnings ? `, ${d.warnings} 警告` : '') + (d.errors ? `, ${d.errors} 错误` : ''), icon);
                    break;
                }
                case 'cmd_start':
                    if (runningWorkflow.value !== 'full_link') currentStep.value++;
                    addLog('info', `执行: <code>${d.command}</code>`, '▶');
                    break;
                case 'cmd_done': {
                    const codeIcon = d.exit_code === 0 ? '✅' : '❌';
                    addLog(d.exit_code === 0 ? 'success' : 'error',
                        `完成 (exit=${d.exit_code}, ${(d.duration_ms||0).toFixed(0)}ms)` +
                        (d.stdout_preview ? `<br><pre style="margin:4px 0 0 24px;font-size:12px;color:#d4d4d4">${d.stdout_preview}</pre>` : ''),
                        codeIcon);
                    break;
                }
                case 'llm_planning':
                    addLog('info', `AI 正在分析故障并生成诊断计划... ${d.files > 0 ? '(含 ' + d.files + ' 个附件)' : ''}`, '🧠');
                    break;
                case 'llm_analyzing':
                    addLog('info', 'AI 正在分析命令输出，设计深挖排查链...', '🧠');
                    break;
                case 'workflow_complete':
                    finished.value = true;
                    if (runningWorkflow.value === 'full_link') currentStep.value = totalSteps.value;
                    addLog('success', `✅ 任务执行完成！共执行 ${currentStep.value} 步`, '🎉');
                    break;
            }
        }

        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / 1048576).toFixed(1) + ' MB';
        }

        function triggerFileInput() {
            fileInput.value?.click();
        }

        function processFiles(fileList) {
            for (const file of fileList) {
                const isImage = file.type.startsWith('image/');
                const entry = { name: file.name, size: file.size, isImage, file };
                uploadedFiles.value.push(entry);

                if (isImage) {
                    const reader = new FileReader();
                    reader.onload = (e) => {
                        entry.dataUrl = e.target.result;
                    };
                    reader.readAsDataURL(file);
                }
            }
        }

        function onFileChange(e) {
            processFiles(e.target.files);
            fileInput.value.value = '';
        }

        function onDrop(e) {
            dragOver.value = false;
            processFiles(e.dataTransfer.files);
        }

        function removeFile(idx) {
            uploadedFiles.value.splice(idx, 1);
        }

        function showFullImage(src) {
            fullImageSrc.value = src;
            fullImageVisible.value = true;
        }

        // 设备
        async function fetchDevices() {
            try { const { data } = await api.get('/api/devices'); devices.value = data; } catch {}
        }

        function onDeviceSelect(val) {
            const d = devices.value.find(x => x.host === val);
            if (d) {
                port.value = d.port;
                username.value = d.username;
                selectedDeviceId.value = d.id;
                // 先清空密码，防止短暂显示旧密码
                password.value = '';
                passwordFromDevice.value = false;
                if (d.has_password) {
                    autoFillPassword(d.id);
                }
            }
        }

        async function autoFillPassword(deviceId) {
            try {
                const { data } = await api.post(`/api/devices/${deviceId}/password`);
                if (data.password) {
                    password.value = data.password;
                    passwordFromDevice.value = true;
                } else {
                    password.value = '';
                    passwordFromDevice.value = false;
                }
            } catch {
                password.value = '';
                passwordFromDevice.value = false;
            }
        }

        watch(() => props.preselectedDevice, (d) => {
            if (d) {
                host.value = d.host;
                port.value = d.port;
                username.value = d.username;
                selectedDeviceId.value = d.id;
                // 先清空密码，防止短暂显示旧密码
                password.value = '';
                passwordFromDevice.value = false;
                if (d.has_password) {
                    autoFillPassword(d.id);
                }
            }
        }, { immediate: true });

        async function startTask() {
            if (running.value) return;
            running.value = true;
            disconnectWS();
            resetProgress();

            // 先生成 session_id，提前连接 WebSocket，再发 API 请求
            const sid = 'ws_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
            await connectWS(sid);  // 等 WebSocket 连上再发请求

            try {
                let resp;
                if (workflowType.value === 'full_link') {
                    resp = await api.post('/api/inspect', {
                        host: host.value, port: port.value,
                        username: username.value, password: password.value,
                        device_id: selectedDeviceId.value,
                        session_id: sid,
                    });
                } else {
                    const formData = new FormData();
                    formData.append('host', host.value);
                    formData.append('port', port.value);
                    formData.append('username', username.value);
                    formData.append('password', password.value);
                    formData.append('error_input', errorInput.value);
                    formData.append('max_iterations', 10);
                    formData.append('device_id', selectedDeviceId.value);
                    formData.append('session_id', sid);
                    for (const f of uploadedFiles.value) {
                        formData.append('files', f.file, f.name);
                    }
                    resp = await api.post('/api/troubleshoot', formData, {
                        headers: { 'Content-Type': 'multipart/form-data' },
                    });
                }
                finished.value = true;
                finalReport.value = resp.data.final_report || '';
                addLog('success', '✅ 任务执行完成！', '🎉');
                ElementPlus.ElMessage.success('任务执行完成！');
                // 通知历史记录页刷新
                window.dispatchEvent(new CustomEvent('task-completed'));
            } catch (e) {
                addLog('error', `执行失败: ${e.response?.data?.detail || e.message}`, '❌');
                ElementPlus.ElMessage.error('执行失败: ' + (e.response?.data?.detail || e.message));
            } finally {
                running.value = false;
            }
        }

        function copyReport() {
            if (!finalReport.value) return;
            navigator.clipboard.writeText(finalReport.value).then(
                () => ElementPlus.ElMessage.success('已复制到剪贴板'),
                () => ElementPlus.ElMessage.error('复制失败')
            );
        }

        function exportReport() {
            if (!finalReport.value) return;
            const blob = new Blob([finalReport.value], { type: 'text/markdown;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
            a.download = `inspect-report-${ts}.md`;
            a.click();
            URL.revokeObjectURL(url);
            ElementPlus.ElMessage.success('报告已导出');
        }

        onMounted(fetchDevices);
        onUnmounted(disconnectWS);
        return {
            devices, host, port, username, password, passwordFromDevice, selectedDeviceId, workflowType, errorInput, running, canStart,
            fileInput, dragOver, uploadedFiles, imagePreviews, fullImageVisible, fullImageSrc,
            showProgress, wsConnected, finished, currentStep, totalSteps, logEntries, layers, runningWorkflow,
            finalReport, renderedReport,
            formatSize, triggerFileInput, onFileChange, onDrop, removeFile, showFullImage,
            onDeviceSelect, startTask, copyReport, exportReport,
        };
    }
};

// ─── 历史记录组件 ────────────────────────────────────────────────────────────

const HistoryPage = {
    template: `
    <div>
        <div class="page-header"><h3>运行历史</h3></div>

        <!-- 筛选栏 -->
        <el-row :gutter="12" style="margin-bottom:16px">
            <el-col :span="5">
                <el-select v-model="filterType" placeholder="工作流类型" clearable @change="fetchPage(1)">
                    <el-option label="全链路巡检" value="full_link" />
                    <el-option label="针对性排查" value="targeted" />
                </el-select>
            </el-col>
            <el-col :span="5">
                <el-select v-model="filterStatus" placeholder="状态" clearable @change="fetchPage(1)">
                    <el-option label="已完成" value="completed" />
                    <el-option label="失败" value="failed" />
                    <el-option label="运行中" value="running" />
                </el-select>
            </el-col>
            <el-col :span="4">
                <el-button @click="fetchPage(1)">刷新</el-button>
            </el-col>
        </el-row>

        <el-table :data="items" stripe v-loading="loading" empty-text="暂无记录">
            <el-table-column label="时间" width="170">
                <template #default="s">{{ s.row.created_at ? s.row.created_at.slice(0,19).replace('T',' ') : '-' }}</template>
            </el-table-column>
            <el-table-column label="设备" width="140">
                <template #default="s">{{ s.row.device_name || s.row.device_host || '-' }}</template>
            </el-table-column>
            <el-table-column label="类型" width="110">
                <template #default="s">
                    <el-tag :type="s.row.workflow_type === 'full_link' ? 'primary' : 'warning'" size="small">
                        {{ s.row.workflow_type === 'full_link' ? '全链路巡检' : '针对性排查' }}
                    </el-tag>
                </template>
            </el-table-column>
            <el-table-column label="故障描述" min-width="180" show-overflow-tooltip>
                <template #default="s">{{ s.row.error_input || '-' }}</template>
            </el-table-column>
            <el-table-column label="状态" width="90">
                <template #default="s">
                    <el-tag :type="s.row.status==='completed'?'success':(s.row.status==='failed'?'danger':'info')" size="small">
                        {{ {completed:'完成',failed:'失败',running:'运行中'}[s.row.status] || s.row.status }}
                    </el-tag>
                </template>
            </el-table-column>
            <el-table-column label="发现" width="70">
                <template #default="s">{{ s.row.findings_count || 0 }}</template>
            </el-table-column>
            <el-table-column label="耗时" width="90">
                <template #default="s">{{ s.row.duration_seconds ? s.row.duration_seconds.toFixed(1)+'s' : '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="160">
                <template #default="s">
                    <el-button size="small" @click="$emit('view-report', s.row.id)">查看报告</el-button>
                    <el-button size="small" type="danger" @click="delRecord(s.row.id)">删除</el-button>
                </template>
            </el-table-column>
        </el-table>

        <el-pagination style="margin-top:16px" background
            layout="total, prev, pager, next"
            :total="total" :page-size="pageSize" :current-page="page"
            @current-change="fetchPage" />
    </div>`,

    emits: ['view-report'],

    setup() {
        const items = ref([]);
        const loading = ref(false);
        const total = ref(0);
        const page = ref(1);
        const pageSize = ref(20);
        const filterType = ref(null);
        const filterStatus = ref(null);

        async function fetchPage(p) {
            if (p) page.value = p;
            loading.value = true;
            try {
                const params = { page: page.value, page_size: pageSize.value };
                if (filterType.value) params.workflow_type = filterType.value;
                if (filterStatus.value) params.status = filterStatus.value;
                const { data } = await api.get('/api/history', { params });
                items.value = data.items;
                total.value = data.total;
            } finally {
                loading.value = false;
            }
        }

        async function delRecord(id) {
            try {
                await ElementPlus.ElMessageBox.confirm('确定删除？', '确认');
                await api.delete(`/api/history/${id}`);
                await fetchPage();
                ElementPlus.ElMessage.success('已删除');
            } catch (e) {
                if (e !== 'cancel') ElementPlus.ElMessage.error('删除失败');
            }
        }

        function onRefresh() { fetchPage(1); }

        onMounted(() => {
            fetchPage();
            window.addEventListener('task-completed', onRefresh);
        });
        onUnmounted(() => {
            window.removeEventListener('task-completed', onRefresh);
        });
        return { items, loading, total, page, pageSize, filterType, filterStatus, fetchPage, delRecord };
    }
};

// ─── 报告详情组件 ────────────────────────────────────────────────────────────

const ReportPage = {
    template: `
    <div>
        <div class="page-header">
            <h3>报告详情</h3>
            <el-button v-if="record" @click="copyReport">复制</el-button>
            <el-button v-if="record" @click="exportReport">导出文件</el-button>
        </div>

        <el-card v-if="!recordId">
            <el-empty description="在"历史记录"中点击"查看报告"" />
        </el-card>

        <el-card v-else-if="loading" v-loading="loading" style="min-height:200px"></el-card>

        <el-card v-else-if="record">
            <!-- 元信息 -->
            <el-descriptions :column="3" border style="margin-bottom:20px">
                <el-descriptions-item label="设备">{{ record.device_name || record.device_host || '-' }}</el-descriptions-item>
                <el-descriptions-item label="类型">
                    {{ record.workflow_type === 'full_link' ? '全链路巡检' : '针对性排查' }}
                </el-descriptions-item>
                <el-descriptions-item label="状态">
                    <el-tag :type="record.status==='completed'?'success':'danger'" size="small">
                        {{ {completed:'完成',failed:'失败',running:'运行中'}[record.status] }}
                    </el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="执行时间">{{ record.created_at?.slice(0,19).replace('T',' ') }}</el-descriptions-item>
                <el-descriptions-item label="耗时">{{ record.duration_seconds ? record.duration_seconds.toFixed(1)+' 秒' : '-' }}</el-descriptions-item>
                <el-descriptions-item label="发现数">{{ record.findings?.length || 0 }}</el-descriptions-item>
            </el-descriptions>

            <!-- 发现列表 -->
            <div v-if="record.findings && record.findings.length > 0" style="margin-bottom:20px">
                <h4>🔍 发现异常:</h4>
                <el-alert v-for="(f, i) in record.findings" :key="i"
                    :title="f" type="warning" :closable="false" style="margin-bottom:6px" />
            </div>

            <!-- 层结果 (全链路) -->
            <div v-if="record.layer_results && Object.keys(record.layer_results).length > 0" style="margin-bottom:20px">
                <h4>📊 各层健康状态:</h4>
                <el-row :gutter="12">
                    <el-col :span="6" v-for="(lr, name) in record.layer_results" :key="name">
                        <el-card shadow="hover">
                            <div style="text-align:center">
                                <div style="font-size:24px">
                                    {{ {ok:'✅',warning:'⚠️',error:'❌'}[lr.status] || '❓' }}
                                </div>
                                <div style="font-weight:bold;margin:8px 0">{{ name.toUpperCase() }}</div>
                                <div style="font-size:12px;color:#909399">
                                    {{ lr.passed }}/{{ lr.total_checks }} 通过
                                </div>
                            </div>
                        </el-card>
                    </el-col>
                </el-row>
            </div>

            <!-- 错误信息 -->
            <el-alert v-if="record.error_message" :title="'错误: ' + record.error_message"
                type="error" :closable="false" style="margin-bottom:20px" />

            <!-- Markdown 报告 -->
            <div v-if="record.final_report" class="markdown-body" v-html="renderedReport"></div>
            <el-empty v-else description="无报告内容" />
        </el-card>
    </div>`,

    props: { recordId: Number },

    setup(props) {
        const record = ref(null);
        const loading = ref(false);
        const renderedReport = computed(() => {
            if (!record.value?.final_report) return '';
            try {
                return marked.parse(record.value.final_report);
            } catch { return record.value.final_report; }
        });

        async function fetchReport() {
            if (!props.recordId) return;
            loading.value = true;
            try {
                const { data } = await api.get(`/api/history/${props.recordId}`);
                record.value = data;
            } catch (e) {
                ElementPlus.ElMessage.error('加载报告失败');
            } finally {
                loading.value = false;
            }
        }

        async function copyReport() {
            if (!record.value?.final_report) return;
            try {
                await navigator.clipboard.writeText(record.value.final_report);
                ElementPlus.ElMessage.success('已复制到剪贴板');
            } catch {
                ElementPlus.ElMessage.error('复制失败');
            }
        }

        function exportReport() {
            if (!record.value?.final_report) return;
            const blob = new Blob([record.value.final_report], { type: 'text/markdown;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
            a.download = `report-${ts}.md`;
            a.click();
            URL.revokeObjectURL(url);
            ElementPlus.ElMessage.success('报告已导出');
        }

        watch(() => props.recordId, fetchReport, { immediate: true });

        return { record, loading, renderedReport, copyReport, exportReport };
    }
};

// ─── 根应用 ──────────────────────────────────────────────────────────────────

const App = {
    components: { DevicesPage, ExecutePage, HistoryPage, ReportPage },

    setup() {
        const activeTab = ref('devices');
        const selectedDevice = ref(null);
        const viewingRecordId = ref(null);
        const sidebarCollapsed = ref(false);

        // API Key 认证
        const showAuthDialog = ref(!savedApiKey);
        const apiKeyInput = ref('');

        function saveApiKey() {
            const key = apiKeyInput.value.trim();
            if (!key) return;
            savedApiKey = key;
            try { sessionStorage.setItem('om_agent_api_key', key); } catch {}
            showAuthDialog.value = false;
            apiKeyInput.value = '';
        }

        // 监听 401 事件，重新显示认证弹窗
        function onAuthRequired() {
            savedApiKey = '';
            apiKeyInput.value = '';
            showAuthDialog.value = true;
        }

        onMounted(() => {
            window.addEventListener('auth-required', onAuthRequired);
        });
        onUnmounted(() => {
            window.removeEventListener('auth-required', onAuthRequired);
        });

        function handleTabSelect(index) { activeTab.value = index; }
        function onSelectDevice(device) {
            selectedDevice.value = device;
            activeTab.value = 'execute';
        }
        function onViewReport(id) {
            viewingRecordId.value = id;
            activeTab.value = 'report';
        }
        function toggleSidebar() {
            sidebarCollapsed.value = !sidebarCollapsed.value;
        }

        return {
            activeTab, selectedDevice, viewingRecordId, sidebarCollapsed,
            showAuthDialog, apiKeyInput, saveApiKey,
            handleTabSelect, onSelectDevice, onViewReport, toggleSidebar,
        };
    }
};

// ─── 启动 ────────────────────────────────────────────────────────────────────

const app = createApp(App);
app.use(ElementPlus, { locale: ElementPlusLocaleZhCn });
app.mount('#app');
