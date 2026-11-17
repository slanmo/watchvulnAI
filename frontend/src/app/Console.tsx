import { useEffect, useState } from "react";
import {
  App as AntApp,
  Alert,
  Avatar,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Dropdown,
  Empty,
  Form,
  Input,
  Layout,
  Menu,
  Modal,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from "antd";
import {
  SafetyCertificateOutlined,
  DashboardOutlined,
  BugOutlined,
  FileTextOutlined,
  SettingOutlined,
  TeamOutlined,
  LogoutOutlined,
  ReloadOutlined,
  ThunderboltOutlined,
  LockOutlined,
  DownOutlined,
} from "@ant-design/icons";
import { api, type Obj } from "../lib/api";
import { Settings, SettingsTabs } from "../settings/Settings";
import {ReportEvents} from '../components/ReportEvents';
import {TaskNotifications} from '../components/TaskNotifications';
import {PublicPortal} from '../components/PublicPortal';
import {CustomReport} from '../components/CustomReport';
function JsonView({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}
export default function Console() {
  const { message, modal } = AntApp.useApp();
  const [status, setStatus] = useState<Obj | null>(null),
    [user, setUser] = useState<Obj | null>(null),
    [page, setPage] = useState(new URLSearchParams(window.location.search).get('view')==='vulnerabilities'?'vulnerabilities':'dashboard'),
    [pending, setPending] = useState<Record<string, number>>({}),
    [config, setConfig] = useState<Obj | null>(null),
    [vulns, setVulns] = useState<Obj[]>([]),
    [reports, setReports] = useState<Obj[]>([]),
    [users, setUsers] = useState<Obj[]>([]),
    [deliveries, setDeliveries] = useState<Obj[]>([]),
    [detail, setDetail] = useState<Obj | null>(null),
    [search, setSearch] = useState(""),
    [selection, setSelection] = useState("all"),
    [passwordOpen, setPasswordOpen] = useState(false),
    [createOpen, setCreateOpen] = useState(false);
  const admin = user?.role === "admin";
  const [events,setEvents]=useState<Obj[]>([]);
  const [collectionJobs,setCollectionJobs]=useState<Obj[]>([]);
  const [sourceHealth,setSourceHealth]=useState<Obj[]>([]);
  const [solutionJobs,setSolutionJobs]=useState<Obj[]>([]);
  const [pushJobs,setPushJobs]=useState<Obj[]>([]);
  const visibleVulns=vulns.filter(v=>(selection==='all'||(selection==='selected'?v.selected:!v.selected))&&(v.title+' '+v.cve+' '+v.description).toLowerCase().includes(search.toLowerCase()));
  const detailRows=page==='vulnerabilities'?visibleVulns:vulns;
  const detailIndex=detailRows.findIndex(v=>v.id===detail?.id);
  const reportRunning=reports.some(r=>['queued','generating'].includes(r.status));
  const collectionRunning=collectionJobs.some(j=>j.status==='running');
  useEffect(()=>{if(!user)return;let stopped=false;async function poll(){try{const rows=await api('/reports');if(!stopped)setReports(rows);if(admin){const jobs=await api('/collection-jobs');if(!stopped)setCollectionJobs(jobs);const pushes=await api('/push-jobs');if(!stopped)setPushJobs(pushes);const solutions=await api('/solution-jobs');if(!stopped)setSolutionJobs(solutions);if(detail?.type==='vuln'){const latest=await api('/vulnerabilities/'+detail.id);if(!stopped)setDetail({type:'vuln',...latest})}const health=await api('/sources/status');if(!stopped)setSourceHealth(health);if(page==='vulnerabilities'){const items=await api('/vulnerabilities');if(!stopped)setVulns(items)}}if(detail?.type==='report'){const r=await api('/reports/'+detail.id);if(!stopped)setDetail({type:'report',...r});if(admin){const logs=await api('/reports/'+detail.id+'/events');if(!stopped)setEvents(logs)}}}catch(e){if(!stopped)console.error(e)}}void poll();const timer=window.setInterval(poll,2000);return()=>{stopped=true;window.clearInterval(timer)}},[user?.id,admin,page,detail?.id]);
  const [dirty, setDirty] = useState(false);
  const group = ["collector", "black", "white", "sources"].includes(page)
    ? "vulnerabilities"
    : ["schedule"].includes(page)
      ? "reports"
      : ["notify", "deliveries"].includes(page)
        ? "notify"
        : page==='auth'?'users':["branding", "settings", "ai_service"].includes(page)
          ? "settings"
          : page;
  function navigate(next: string) {
    if (next === page) return;
    if (dirty) {
      modal.confirm({
        title: "放弃未保存的配置？",
        okText: "放弃修改",
        cancelText: "继续编辑",
        onOk: () => {
          setDirty(false);
          setPage(next);
        },
      });
    } else setPage(next);
  }
  useEffect(() => {
    const guard = (event: BeforeUnloadEvent) => {
      if (dirty) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", guard);
    return () => window.removeEventListener("beforeunload", guard);
  }, [dirty]);
  async function logout() {
    await api("/logout", "POST");
    setDirty(false);
    setUser(null);
    setConfig(null);
    setDetail(null);
    setVulns([]);
    setUsers([]);
    setDeliveries([]);
    setReports([]);
    setPage("dashboard");
    setSearch("");
    setSelection("all");
    setPasswordOpen(false);
    setCreateOpen(false);
    const s = await api("/status");
    setStatus(s);
    if (s.report_access === "public") setReports(await api("/reports"));
  }
  const isPending = (key: string) => (pending[key] || 0) > 0;
  async function action(fn: () => Promise<void>, key = "background") {
    setPending(values => ({...values, [key]: (values[key] || 0) + 1}));
    try {
      await fn();
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setPending(values => ({...values, [key]: Math.max(0, (values[key] || 0) - 1)}));
    }
  }
  async function refresh(u = user) {
    if (!u) return;
    const paths =
      u.role === "admin"
        ? ["/config", "/vulnerabilities", "/reports", "/users", "/deliveries"]
        : ["/reports"];
    const a = await Promise.all(paths.map((p) => api(p)));
    if (u.role === "admin") {
      setConfig(a[0]);
      setVulns(a[1]);
      setReports(a[2]);
      setUsers(a[3]);
      setDeliveries(a[4]);
    } else {
      setReports(a[0]);
      setPage("reports");
    }
  }
  useEffect(() => {
    action(async () => {
      const s = await api("/status");
      setStatus(s);
      document.title = s.branding.title;
      if (s.initialized) {
        let u = null;
        try {
          u = await api("/me");
        } catch {
          if (s.report_access === "public") setReports(await api("/reports"));
        }
        if (u) {
          setUser(u);
          await refresh(u);
        }
      }
    });
  }, []);
  const branding = config?.branding ||
    status?.branding || { title: "WatchVuln AI" };
  useEffect(() => {
    document.title = branding.title;
  }, [branding.title]);
  const logo = (
    <div className="brand">
      {branding.logo ? (
        <img src={branding.logo} alt="Logo" />
      ) : (
        <SafetyCertificateOutlined />
      )}
      <span>
        {branding.title}
        <small>VULNERABILITY INTELLIGENCE</small>
      </span>
    </div>
  );
  if (!status)
    return (
      <div className="center">
        <Spin size="large" />
      </div>
    );
  if (!status.initialized)
    return (
      <div className="auth">
        <div className="auth-intro">
          {logo}
          <h1>
            把漏洞情报，
            <br />
            变成可执行的决策。
          </h1>
          <p>统一采集 · 精准筛选 · AI 风险研判 · 多渠道通知</p>
        </div>
        <Card title="初始化您的工作空间" className="auth-card">
          <Alert
            type="info"
            showIcon
            message="首次启动配置"
            description="选择数据库并设置内置管理员密码。初始化完成后，其他配置均可在控制台修改。"
          />
          <Form
            layout="vertical"
            initialValues={{
              database: "sqlite",
              title: "WatchVuln AI",
              password: "Root_2025",
            }}
            onFinish={(v) =>
              action(async () => {
                await api("/setup", "POST", v);
                setStatus(await api("/status"));
                message.success("初始化成功，请登录");
              }, "setup")
            }
          >
            <Form.Item
              name="title"
              label="平台标题"
              rules={[{ required: true }]}
            >
              <Input />
            </Form.Item>
            <Form.Item
              name="database"
              label="数据库"
              rules={[{ required: true }]}
            >
              <Select
                options={[
                  { value: "sqlite", label: "SQLite · 单机轻量存储" },
                  { value: "postgres", label: "PostgreSQL · 生产数据库" },
                ]}
              />
            </Form.Item>
            <Form.Item noStyle shouldUpdate>
              {({ getFieldValue }) =>
                getFieldValue("database") === "postgres" ? (
                  <Form.Item
                    name="dsn"
                    label="PostgreSQL 连接串"
                    rules={[{ required: true }]}
                  >
                    <Input.Password placeholder="postgres://user:password@host:5432/watchvuln?sslmode=require" />
                  </Form.Item>
                ) : (
                  <Form.Item name="dsn" label="SQLite 路径（留空使用数据目录）">
                    <Input placeholder="由服务端保存到 data/watchvuln.db" />
                  </Form.Item>
                )
              }
            </Form.Item>
            <Form.Item label="管理员账号">
              <Input value="admin" disabled />
            </Form.Item>
            <Form.Item
              name="password"
              label="管理员密码"
              rules={[{ required: true, min: 9, max: 72 }]}
            >
              <Input.Password />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={isPending("setup")}>
              创建工作空间
            </Button>
          </Form>
        </Card>
      </div>
    );
  if (window.location.pathname==='/public' && (user||status.report_access==='public')) return <PublicPortal branding={branding} reports={reports}/>;
  if(window.location.pathname==='/public'&&!user&&status.report_access!=='public')return <div className="center"><Card title="公开浏览未开启"><Typography.Paragraph>管理员需在系统设置 → 访问设置，将“情报与报告访问”改为公开访问。当前内容需登录查看。</Typography.Paragraph><Button href="/">前往登录</Button></Card></div>;
  if (!user)
    return (
      <div className="auth">
        <div className="auth-intro">
          {logo}
          <h1>
            让安全情报，
            <br />
            始终领先一步。
          </h1>
          <p>从分散的漏洞公告，到清晰的风险分析与修复建议。</p>
        </div>
        <Card title="登录控制台" className="auth-card">
          <Form
            layout="vertical"
            initialValues={{ provider: "local", username: "admin" }}
            onFinish={(v) =>
              action(async () => {
                const u = await api("/login", "POST", v);
                setUser(u);
                await refresh(u);
              }, "login")
            }
          >
            <Form.Item name="provider" label="登录方式">
              <Select
                options={[
                  { value: "local", label: "本地账户" },
                  ...(status.providers.includes("ldap")
                    ? [{ value: "ldap", label: "LDAP 目录账户" }]
                    : []),
                ]}
              />
            </Form.Item>
            <Form.Item
              name="username"
              label="用户名"
              rules={[{ required: true }]}
            >
              <Input autoComplete="username" />
            </Form.Item>
            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true }]}
            >
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            <Button htmlType="submit" type="primary" block loading={isPending("login")}>
              登录
            </Button>
          </Form>
          <Space wrap style={{ marginTop: 20 }}>
            {status.providers
              .filter((p: string) => p !== "ldap")
              .map((p: string) => (
                <Button key={p} href={"/api/oauth/" + p + "/start"}>
                  {
                    ({ oidc: "OIDC", feishu: "飞书", dingtalk: "钉钉" } as Obj)[
                      p
                    ]
                  }
                  登录
                </Button>
              ))}
          </Space>
          {status.report_access === 'public'&&<Button block href="/public" style={{marginTop:20}}>浏览公开情报</Button>}
        </Card>
      </div>
    );
  const titles: Obj = {
    dashboard: "概览",
    vulnerabilities: "漏洞情报",
    reports: "AI报告",
    settings: "系统设置",
    notify: "通知服务",
    users: "用户权限",
  };
  const groupTabs =
    group === "vulnerabilities"
      ? [
          { key: "vulnerabilities", label: "漏洞列表" },
          { key: "black", label: "黑名单" },
          { key: "white", label: "白名单" },
          { key: "sources", label: "源状态" },
          { key: "collector", label: "采集配置" },
        ]
      : group === "reports"
        ? [
            { key: "reports", label: "分析报告" },
            { key: "schedule", label: "定时报告" },
          ]
        : group === "notify"
          ? [
              { key: "notify", label: "通知服务" },
              { key: "deliveries", label: "通知记录" },
            ]
          : group==='users'?[{key:'users',label:'用户管理'},{key:'auth',label:'SSO源'}]:[];
  return (
    <Layout className="shell">
      <Layout.Sider
        width={250}
        breakpoint="lg"
        collapsedWidth={76}
        className="sidebar"
      >
        {logo}
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[group]}
          onClick={(v) => navigate(v.key === "settings" ? "branding" : v.key)}
          items={[
            ...(admin
              ? [
                  {
                    key: "dashboard",
                    icon: <DashboardOutlined />,
                    label: "概览",
                  },
                  {
                    key: "vulnerabilities",
                    icon: <BugOutlined />,
                    label: "漏洞情报",
                  },
                ]
              : []),
            {
              key: "reports",
              icon: <FileTextOutlined />,
              label: "AI报告",
            },
            ...(admin
              ? [
                  {
                    key: "notify",
                    icon: <ThunderboltOutlined />,
                    label: "通知服务",
                  },
                  { key: "users", icon: <TeamOutlined />, label: "用户权限" },
                  {
                    key: "settings",
                    icon: <SettingOutlined />,
                    label: "系统设置",
                  },
                ]
              : []),
          ]}
        />
      </Layout.Sider>
      <Layout>
        <Layout.Header className="topbar">
          <span>
            安全运营 / <b>{titles[group]}</b>
          </span>
          <Space>
            <Button
              icon={<ReloadOutlined />}
              loading={isPending("refresh")}
              disabled={dirty}
              onClick={() => action(() => refresh(), "refresh")}
            >
              刷新
            </Button>
            <TaskNotifications reports={reports} jobs={admin?[...collectionJobs,...pushJobs]:[]} health={admin?sourceHealth:[]} onReport={r=>{setEvents([]);setDetail({type:'report',...r})}}/>
            <Dropdown
              trigger={["click"]}
              menu={{
                items: [
                  ...(user.provider === "local"
                    ? [
                        {
                          key: "password",
                          icon: <LockOutlined />,
                          label: "修改密码",
                        },
                      ]
                    : []),
                  {
                    key: "logout",
                    icon: <LogoutOutlined />,
                    label: "退出登录",
                    danger: true,
                  },
                ],
                onClick: ({ key }) =>
                  key === "password" ? setPasswordOpen(true) : action(logout),
              }}
            >
              <Button type="text" className="account-trigger">
                <Space>
                  <Avatar
                    size="small"
                    style={{ background: "#dbeafe", color: "#1d4ed8" }}
                  >
                    {user.display_name?.[0] || user.username[0]}
                  </Avatar>
                  {admin ? "管理员" : user.display_name || user.username}
                  <DownOutlined />
                </Space>
              </Button>
            </Dropdown>
          </Space>
        </Layout.Header>
        <Layout.Content className="content">
          <div className="page-heading">
            <div>
              <Typography.Title level={2}>{titles[group]}</Typography.Title>
            </div>
          </div>
          {group==='reports'&&<Alert showIcon type="warning" message="使用AI分析报告会大量消耗词元(Token)，请谨慎使用。" style={{marginBottom:16,fontWeight:600}}/>}
          {admin && groupTabs.length > 0 && (
            <Tabs activeKey={page} onChange={navigate} items={groupTabs} />
          )}
          {admin && group === "settings" && (
            <SettingsTabs section={page} onChange={navigate} />
          )}
          {page === "dashboard" && (
            <>
              <Row gutter={[20, 20]}>
                {[
                  {
                    label: "已采集漏洞",
                    value: vulns.length,
                    color: "#2563eb",
                  },
                  {
                    label: "筛选通过",
                    value: vulns.filter((v) => v.selected).length,
                    color: "#059669",
                  },
                  {
                    label: "分析报告",
                    value: reports.filter((r) => r.status === "ready").length,
                    color: "#7c3aed",
                  },
                  {
                    label: "投递失败",
                    value: deliveries.filter((d) => d.status === "failed")
                      .length,
                    color: "#e25a45",
                  },
                ].map((v) => (
                  <Col xs={24} sm={12} xl={6} key={v.label}>
                    <Card>
                      <Statistic
                        title={v.label}
                        value={v.value}
                        valueStyle={{ color: v.color, fontWeight: 700 }}
                      />
                    </Card>
                  </Col>
                ))}
              </Row>
              <Row gutter={[20, 20]} style={{ marginTop: 24 }} className="overview-workflow">
                <Col xs={24} xl={16}>
                  <Card
                    title="最新漏洞情报"
                    extra={
                      <Button
                        type="link"
                        onClick={() => setPage("vulnerabilities")}
                      >
                        查看全部
                      </Button>
                    }
                  >
                    <Table
                      rowKey="id"
                      dataSource={vulns.slice(0, 6)}
                      pagination={false}
                      columns={[
                        {
                          title: "漏洞标题",
                          dataIndex: "title",
                          onCell: () => ({ style: { width: "100%" } }),
                          render: (v, r) => (
                            <a className="vulnerability-title" title={v}
                              onClick={() => setDetail({ type: "vuln", ...r })}
                            >
                              {v}
                            </a>
                          ),
                        },
                        {
                          title: "来源",
                          dataIndex: "source",
                          onCell: () => ({ style: { whiteSpace: "nowrap" } }),
                          render: (v) => <Tag>{v}</Tag>,
                        },
                        {
                          title: "筛选",
                          dataIndex: "selected",
                          onCell: () => ({ style: { whiteSpace: "nowrap" } }),
                          render: (v) => (
                            <Tag color={v ? "green" : "default"}>
                              {v ? "通过" : "排除"}
                            </Tag>
                          ),
                        },
                      ]}
                    />
                  </Card>
                </Col>
                <Col xs={24} xl={8}>
                  <Card title="工作流状态">
                    <Descriptions
                      column={1}
                      items={[
                        {
                          key: 1,
                          label: "采集服务",
                          children: (
                            <Tag
                              color={
                                config?.collector.enabled ? "green" : "default"
                              }
                            >
                              {config?.collector.enabled ? "已启用" : "已暂停"}
                            </Tag>
                          ),
                        },
                        {
                          key: 2,
                          label: "采集间隔",
                          children: config?.collector.interval,
                        },
                        {
                          key: 3,
                          label: "AI 分析",
                          children: config?.ai.enabled ? "已接入" : "未启用",
                        },
                        {
                          key: 4,
                          label: "通知渠道",
                          children:
                            config?.notifications.filter((n: Obj) => n.enabled)
                              .length + " 个启用",
                        },
                        {
                          key: 5,
                          label: "报告访问",
                          children:
                            config?.auth.report_access === "public"
                              ? "公开访问"
                              : "仅登录用户",
                        },
                      ]}
                    />
                    <Button
                      type="primary"
                      block
                      style={{ marginTop: 24 }}
                      onClick={() => navigate("collector")}
                    >
                      采集配置
                    </Button>
                  </Card>
                </Col>
              </Row>
            </>
          )}
          {admin&&page==='sources'&&<Card title="漏洞源状态" extra={<Button loading={isPending('source-check')||sourceHealth.some(h=>h.status==='checking')} onClick={()=>action(async()=>{await api('/sources/check','POST');setSourceHealth(await api('/sources/status'));message.success('源检查已提交，不会入库或发送通知')},'source-check')}>检查已配置来源</Button>}><Table rowKey="source" dataSource={(config?.collector.sources||[]).map((src:string)=>sourceHealth.find(h=>h.source===(src==='ti'?'nox':src))||{source:src,status:'unknown'})} columns={[{title:'来源',dataIndex:'source'},{title:'状态',dataIndex:'status',render:s=><Tag color={s==='healthy'?'green':s==='failed'?'red':s==='checking'?'processing':'default'}>{({healthy:'正常',failed:'失败',checking:'检查中',empty:'无结果',unknown:'未检查'} as Obj)[s]}</Tag>},{title:'结果数',dataIndex:'count'},{title:'耗时(ms)',dataIndex:'duration_ms'},{title:'原因',dataIndex:'error'},{title:'检查时间',dataIndex:'checked_at',render:t=>t?new Date(t).toLocaleString():'—'}]}/></Card>}
          {page === "vulnerabilities" && (
            <Card>
              <Space wrap className="toolbar">
                <Input.Search
                  placeholder="搜索标题 / CVE / 描述"
                  allowClear
                  onChange={(e) => setSearch(e.target.value)}
                  style={{ width: 320 }}
                />
                <Select
                  value={selection}
                  onChange={setSelection}
                  options={[
                    { value: "all", label: "全部筛选结果" },
                    { value: "selected", label: "仅通过" },
                    { value: "excluded", label: "仅排除" },
                  ]}
                />
                <Button
                  type="primary"
                  icon={<ReloadOutlined />}
                  loading={isPending("collect") || collectionRunning}
                  onClick={() =>
                    action(async () => {
                      const job=await api("/collect", "POST");
                      setCollectionJobs(rows=>[job,...rows]);
                      message.success("采集任务已提交");
                    }, "collect")
                  }
                >
                  立即采集
                </Button>
                <Button loading={isPending('refilter')} onClick={()=>modal.confirm({title:'重新标记已有漏洞？',content:'使用已保存的全部黑白名单、高价值和CVE去重配置重算通过或排除，会覆盖人工筛选状态，不发送通知。请先保存规则修改。',okText:'重新标记',cancelText:'取消',onOk:()=>action(async()=>{const result=await api('/vulnerabilities/refilter','POST');setVulns(await api('/vulnerabilities'));message.success(`重新标记完成，更新${result.changed}条记录`)},'refilter')})}>重新标记</Button>
              </Space>
              <Table
                rowKey="id"
                dataSource={vulns.filter(
                  (v) =>
                    (selection === "all" ||
                      v.selected === (selection === "selected")) &&
                    [v.title, v.cve, v.description]
                      .join(" ")
                      .toLowerCase()
                      .includes(search.toLowerCase()),
                )}
                columns={[
                  {
                    title: "漏洞标题",
                    dataIndex: "title",
                    onCell: () => ({ style: { width: "100%" } }),
                    render: (v, r) => (
                      <a className="vulnerability-title" title={v} onClick={() => setDetail({ type: "vuln", ...r })}>
                        {v}
                      </a>
                    ),
                  },
                  { title: "CVE", dataIndex: "cve", onCell: () => ({ style: { whiteSpace: "nowrap" } }) },
                  { title: "来源", dataIndex: "source", onCell: () => ({ style: { whiteSpace: "nowrap" } }) },
                  {
                    title: "筛选结果",
                    dataIndex: "selected",
                    onCell: () => ({ style: { whiteSpace: "nowrap" } }),
                    render: (v, r) => (
                      <Tag
                        color={v ? "green" : "default"}
                        title={r.filter_reason}
                      >
                        {v ? "通过" : "排除"}
                      </Tag>
                    ),
                  },
                  {title:'筛选原因',dataIndex:'filter_reason',onCell:()=>({style:{whiteSpace:'nowrap'}}),render:(v)=><span title={v}>{v||'—'}</span>},
                  {title:'手动筛选',onCell:()=>({style:{whiteSpace:'nowrap'}}),render:(_,r)=><Switch checked={r.selected} checkedChildren="通过" unCheckedChildren="排除" onChange={selected=>action(async()=>{const updated=await api('/vulnerabilities/'+r.id,'PATCH',{selected});setVulns(rows=>rows.map(v=>v.id===r.id?updated:v));message.success(selected?'已设为通过':'已手动排除')},'filter:'+r.id)} loading={isPending('filter:'+r.id)}/>},
                  {
                    title: "采集时间",
                    dataIndex: "created_at",
                    onCell: () => ({ style: { whiteSpace: "nowrap" } }),
                    render: (v) => new Date(v).toLocaleString(),
                  },
                  {title:'操作',onCell:()=>({style:{whiteSpace:'nowrap'}}),render:(_,r)=><Button size="small" loading={isPending('push:'+r.id)||pushJobs.some(j=>j.vulnerability_id===r.id&&j.status==='running')} onClick={()=>modal.confirm({title:'推送此漏洞？',content:'将推送至全部启用渠道。通过记录且开启AI时先分析，失败按原内容推送；排除记录直接推送，不改变筛选状态。',okText:'推送',cancelText:'取消',onOk:()=>action(async()=>{const j=await api('/vulnerabilities/'+r.id+'/push','POST');setPushJobs(rows=>[j,...rows]);message.success('推送任务已提交，可在通知与任务查看结果')},'push:'+r.id)})}>推送</Button>},
                ]}
                pagination={{
                  pageSize: 15,
                  showSizeChanger: true,
                  showTotal: (n) => `共 ${n} 条`,
                }}
              />
            </Card>
          )}
          {page === "reports" && (
            <Card
              title="报告中心"
              extra={
                admin && (
                  <Space>
                    <Button
                      loading={isPending("daily")}
                      disabled={isPending("weekly") || reportRunning}
                      onClick={() =>
                        action(async () => {
                          try {
                            const r = await api("/reports", "POST", {kind: "daily"});
                            setDetail({ type: "report", ...r });
                          } finally {
                            setReports(await api("/reports"));
                          }
                        }, "daily")
                      }
                    >
                      生成日报
                    </Button>
                    <Button
                      type="primary"
                      loading={isPending("weekly")}
                      disabled={isPending("daily") || reportRunning}
                      onClick={() =>
                        action(async () => {
                          try {
                            const r = await api("/reports", "POST", {kind: "weekly"});
                            setDetail({ type: "report", ...r });
                          } finally {
                            setReports(await api("/reports"));
                          }
                        }, "weekly")
                      }
                    >
                      生成周报
                    </Button>
                    <CustomReport disabled={reportRunning} generate={async(start,end)=>{try{const r=await api('/reports','POST',{kind:'custom',start_date:start,end_date:end});setEvents([]);setDetail({type:'report',...r});setReports(await api('/reports'))}catch(error){message.error((error as Error).message);throw error}}}/>
                  </Space>
                )
              }
            >
              <Table
                rowKey="id"
                dataSource={reports}
                columns={[
                  {
                    title: "报告标题",
                    dataIndex: "title",
                    render: (v, r) => (
                      <a
                        onClick={() =>
                          action(async () =>
                            setDetail({
                              type: "report",
                              ...(await api("/reports/" + r.id)),
                            }),
                          )
                        }
                      >
                        {v}
                      </a>
                    ),
                  },
                  {
                    title: "类型",
                    dataIndex: "kind",
                    render: (v) => (
                      <Tag color="blue">{v === "daily" ? "日报" : v==='weekly'?'周报':'周期报告'}</Tag>
                    ),
                  },
                  {
                    title: "状态",
                    dataIndex: "status",
                    render: (v) => (
                      <Tag
                        color={
                          v === "ready"
                            ? "green"
                            : v === "failed"
                              ? "red"
                              : "processing"
                        }
                      >
                        {v}
                      </Tag>
                    ),
                  },
                  {
                    title: "失败原因",
                    dataIndex: "error",
                    width: 320,
                    render: (value) => value ? <Typography.Text type="danger" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{value}</Typography.Text> : "—",
                  },
                  {
                    title: "生成时间（东八区）",
                    dataIndex: "created_at",
                    render: (v) => new Date(v).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}),
                  },
                  {
                    title: "操作",
                    render: (_, r) => (
                      <Space>
                        {admin&&['queued','generating'].includes(r.status)&&<Button danger loading={isPending('cancel:'+r.id)} onClick={()=>action(async()=>{await api('/reports/'+r.id+'/cancel','POST');message.success('已请求取消生成');setReports(await api('/reports'))},'cancel:'+r.id)}>取消生成</Button>}
                        {admin&&<Button danger disabled={['queued','generating'].includes(r.status)} onClick={()=>modal.confirm({title:'删除报告及其生成日志？',okText:'删除',okButtonProps:{danger:true},onOk:async()=>{try{await api('/reports/'+r.id,'DELETE');setReports(rows=>rows.filter(item=>item.id!==r.id));if(detail?.id===r.id)setDetail(null);message.success('报告已删除')}catch(error){message.error((error as Error).message);throw error}}})}>删除</Button>}
                        <Button
                          href={"/api/reports/" + r.id + "/html"}
                          target="_blank"
                          disabled={r.status !== "ready"}
                        >
                          全文
                        </Button>
                        {admin && (
                          <Button
                            disabled={r.status !== "ready"}
                            onClick={() =>
                              action(async () => {
                                await api("/reports/" + r.id + "/send", "POST");
                                await refresh();
                                message.success("已投递");
                              })
                            }
                          >
                            推送
                          </Button>
                        )}
                      </Space>
                    ),
                  },
                ]}
              />
            </Card>
          )}
          {page === "deliveries" && (
            <Card>
              <Table
                rowKey="id"
                dataSource={deliveries}
                columns={[
                  {
                    title: "通知渠道",
                    dataIndex: "channel_id",
                    render: (v) =>
                      config?.notifications.find((n: Obj) => n.id === v)
                        ?.name || v,
                  },
                  {
                    title: "报告",
                    dataIndex: "report_id",
                    render: (v) =>
                      reports.find((r) => r.id === v)?.title ||
                      (v ? "已删除报告" : "实时漏洞通知"),
                  },
                  {
                    title: "投递状态",
                    dataIndex: "status",
                    render: (v) => (
                      <Tag color={v === "sent" ? "green" : "red"}>
                        {v === "sent" ? "成功" : "失败"}
                      </Tag>
                    ),
                  },
                  { title: "错误信息", dataIndex: "error" },
                  {
                    title: "时间",
                    dataIndex: "created_at",
                    render: (v) => new Date(v).toLocaleString(),
                  },
                ]}
              />
            </Card>
          )}
          {admin &&
            [
              "collector",
              "black",
              "white",
              "schedule",
              "notify",
              "branding",
              "ai_service",
              "auth",
            ].includes(page) &&
            config && (
              <Settings
                key={page}
                config={config}
                section={page}
                onDirtyChange={setDirty}
                busy={isPending("save:" + page)}
                testing={(id) => isPending("test:" + id)}
                save={(v) =>
                  action(async () => {
                    setConfig(await api("/config", "PUT", v));
                    setStatus(await api("/status"));
                    message.success("配置已保存");
                  }, "save:" + page)
                }
                test={(n) =>
                  action(async () => {
                    await api("/notifications/test", "POST", n);
                    message.success("测试消息发送成功");
                  }, "test:" + n.id)
                }
              />
            )}
          {page === "users" && (
            <Card
              title="账户目录"
              extra={
                <Button type="primary" onClick={() => setCreateOpen(true)}>
                  新增本地用户
                </Button>
              }
            >
              <Table
                rowKey="id"
                dataSource={users}
                columns={[
                  { title: "用户名", dataIndex: "username" },
                  { title: "显示名称", dataIndex: "display_name" },
                  {
                    title: "身份来源",
                    dataIndex: "provider",
                    render: (v) => <Tag>{v}</Tag>,
                  },
                  {
                    title: "角色",
                    dataIndex: "role",
                    render: (v, r) => (
                      <Select
                        value={v}
                        disabled={
                          r.username === "admin" && r.provider === "local"
                        }
                        options={[
                          { value: "admin", label: "管理员" },
                          { value: "user", label: "普通用户" },
                        ]}
                        onChange={(role) =>
                          action(async () => {
                            await api("/users/" + r.id, "PATCH", {
                              role,
                              disabled: r.disabled,
                            });
                            await refresh();
                          })
                        }
                      />
                    ),
                  },
                  {
                    title: "允许登录",
                    dataIndex: "disabled",
                    render: (v, r) => (
                      <Switch
                        checked={!v}
                        disabled={
                          r.username === "admin" && r.provider === "local"
                        }
                        onChange={(checked) =>
                          action(async () => {
                            await api("/users/" + r.id, "PATCH", {
                              role: r.role,
                              disabled: !checked,
                            });
                            await refresh();
                          })
                        }
                      />
                    ),
                  },
                ]}
              />
            </Card>
          )}
        </Layout.Content>
        <Layout.Footer style={{ textAlign: "center" }}>
          WatchVuln AI · 漏洞情报与风险分析工作空间
        </Layout.Footer>
      </Layout>
      <Drawer
        width="min(100vw,1000px)"
        open={!!detail}
        onClose={() => setDetail(null)}
        title={detail?.title}
        extra={detail?.type==='vuln'?<Space>{admin&&<Button size="small" type="primary" loading={isPending('push:'+detail.id)||pushJobs.some(j=>j.vulnerability_id===detail.id&&j.status==='running')} onClick={()=>modal.confirm({title:'推送此漏洞？',content:'将发送到全部启用渠道；仅通过的记录自动补充AI分析，失败使用原内容推送。',okText:'推送',cancelText:'取消',onOk:()=>action(async()=>{const j=await api('/vulnerabilities/'+detail.id+'/push','POST');setPushJobs(rows=>[j,...rows]);message.success('推送任务已提交')},'push:'+detail.id)})}>推送</Button>}<Button size="small" disabled={detailIndex<=0} onClick={()=>setDetail({type:'vuln',...detailRows[detailIndex-1]})}>上一个</Button><Button size="small" disabled={detailIndex<0||detailIndex>=detailRows.length-1} onClick={()=>setDetail({type:'vuln',...detailRows[detailIndex+1]})}>下一个</Button></Space>:undefined}
      >
        {detail?.type === "vuln" ? (
          <>
            <Descriptions
              column={1}
              bordered
              items={[
                "source",
                "cve",
                "severity",
                "published_at",
                "filter_reason",
                "url",
              ].map((k) => ({ key: k, label: k, children: detail[k] }))}
            />
            <Typography.Title level={4}>漏洞描述</Typography.Title>
            <p className="preserve">{detail.description||'来源暂未提供描述'}</p>
            <div style={{display:'flex',alignItems:'center',gap:12,margin:'24px 0 12px'}}><Typography.Title level={4} style={{margin:0}}>修复方案</Typography.Title>{admin&&config?.collector.ai_solution&&detail.selected&&!detail.ai_analysis&&<Button type="default" size="small" loading={isPending('solution:'+detail.id)||solutionJobs.some(j=>j.vulnerability_id===detail.id&&j.status==='running')} onClick={()=>modal.confirm({title:'生成AI漏洞分析',content:<Typography.Paragraph style={{margin:0}}>将使用当前AI模型分析影响范围、风险、复现方式与修改方案，消耗Token，任务在后台执行。</Typography.Paragraph>,okText:'开始生成',cancelText:'取消',centered:true,width:400,onOk:()=>action(async()=>{const job=await api('/vulnerabilities/'+detail.id+'/solution','POST');setSolutionJobs(rows=>[job,...rows]);message.success('后台任务已提交，可继续浏览')},'solution:'+detail.id)})}>AI生成</Button>}</div>
            {solutionJobs.find(j=>j.vulnerability_id===detail.id)?.status==='failed'&&<Alert type="error" showIcon message={solutionJobs.find(j=>j.vulnerability_id===detail.id)?.error}/>}
            {solutionJobs.some(j=>j.vulnerability_id===detail.id&&j.status==='running')&&<Typography.Paragraph type="secondary">正在后台生成AI漏洞分析…</Typography.Paragraph>}
            <p className="preserve">
              {detail.solution || "来源没有提供修复方案"}
            </p>
            {detail.ai_analysis&&<Alert type="info" style={{marginTop:16}} message={<Typography.Text strong>AI生成的漏洞分析</Typography.Text>} description={<div className="preserve">{`影响范围：${detail.ai_analysis.impact||'未提供'}\n\n风险：${detail.ai_analysis.risk||'未提供'}\n\n复现方式：${detail.ai_analysis.reproduction||'未提供'}\n\n修改方案：${detail.ai_analysis.remediation||'未提供'}\n\n—— 内容由AI生成，仅供参考，请结合厂商公告与实际资产复核。`}</div>}/>}
            <Typography.Title level={4}>参考链接</Typography.Title>
            {detail.references?.length?<ol>{detail.references.map((link:string)=><li key={link}><Typography.Link href={/^https?:\/\//i.test(link)?link:undefined} target="_blank" rel="noopener noreferrer">{link}</Typography.Link></li>)}</ol>:<Typography.Paragraph type="secondary">来源暂未提供参考链接</Typography.Paragraph>}
            <Space wrap>
              {detail.tags?.map((t: string) => <Tag key={t}>{t}</Tag>)}
            </Space>
          </>
        ) : (
          detail && (
            <>
              <Alert
                type={detail.status === "failed" ? "error" : "info"}
                message={detail.error || detail.summary}
              />
              <Tabs
                defaultActiveKey={admin?'events':'html'}
                items={[
                  ...(admin?[{key:'events',label:'生成记录',children:<ReportEvents events={events}/>}]:[]),
                  {
                    key: "html",
                    label: "完整报告",
                    children: (
                      <iframe
                        title="完整报告"
                        sandbox="allow-same-origin"
                        src={"/api/reports/" + detail.id + "/html"}
                        className="report-frame"
                      />
                    ),
                  },
                  {
                    key: "feishu",
                    label: "飞书卡片预览",
                    children: (
                      <>
                        <Card className="preview-card" title={detail.title}>
                          <p>{detail.summary}</p>
                          <Button
                            type="primary"
                            href={"/api/reports/" + detail.id + "/html"}
                            target="_blank"
                          >
                            查看完整分析报告
                          </Button>
                        </Card>
                        <JsonView value={detail.feishu_card} />
                      </>
                    ),
                  },
                  {
                    key: "ding",
                    label: "钉钉卡片预览",
                    children: (
                      <>
                        <Card className="preview-card" title={detail.title}>
                          <p>{detail.summary}</p>
                          <Button
                            href={"/api/reports/" + detail.id + "/html"}
                            target="_blank"
                          >
                            查看完整分析报告
                          </Button>
                        </Card>
                        <JsonView value={detail.dingtalk_card} />
                      </>
                    ),
                  },
                ]}
              />
            </>
          )
        )}
      </Drawer>
      <Modal
        title="修改本地账户密码"
        open={passwordOpen}
        footer={null}
        destroyOnClose
        onCancel={() => setPasswordOpen(false)}
      >
        <Form
          layout="vertical"
          onFinish={(v) =>
            action(async () => {
              await api("/password", "PUT", v);
              setPasswordOpen(false);
              message.success("密码已更新，其他会话已失效");
            }, "password")
          }
        >
          <Form.Item
            name="old_password"
            label="原密码"
            rules={[{ required: true }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="password"
            label="新密码"
            rules={[{ required: true, min: 9, max: 72 }]}
          >
            <Input.Password />
          </Form.Item>
          <Button htmlType="submit" type="primary" loading={isPending("password")}>
            更新密码
          </Button>
        </Form>
      </Modal>
      <Modal
        title="新增本地用户"
        open={createOpen}
        footer={null}
        destroyOnClose
        onCancel={() => setCreateOpen(false)}
      >
        <Form
          layout="vertical"
          onFinish={(v) =>
            action(async () => {
              await api("/users", "POST", v);
              setCreateOpen(false);
              await refresh();
              message.success("用户已创建");
            }, "create-user")
          }
        >
          {["username", "display_name", "password"].map((k) => (
            <Form.Item
              key={k}
              name={k}
              label={
                (
                  {
                    username: "用户名",
                    display_name: "显示名称",
                    password: "初始密码",
                  } as Obj
                )[k]
              }
              rules={
                k === "password"
                  ? [{ required: true, min: 9, max: 72 }]
                  : [{ required: true }]
              }
            >
              {k === "password" ? <Input.Password /> : <Input />}
            </Form.Item>
          ))}
          <Button htmlType="submit" type="primary" loading={isPending("create-user")}>
            创建普通用户
          </Button>
        </Form>
      </Modal>
    </Layout>
  );
}
