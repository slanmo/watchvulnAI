import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Tabs,
  Typography,
} from "antd";
import {CollectionTime} from '../components/CollectionTime';
import type { Obj } from "../lib/api";
import { channelFields, channelNames, sources } from "../lib/constants";

type Props = {
  config: Obj;
  section: string;
  busy: boolean;
  testing: (id: string) => boolean;
  save: (value: Obj) => void;
  test: (value: Obj) => void;
  onDirtyChange: (dirty: boolean) => void;
};
export function Settings({
  config,
  section,
  busy,
  testing,
  save,
  test,
  onDirtyChange,
}: Props) {
  const [form] = Form.useForm();
  useEffect(() => {
    form.resetFields();
    form.setFieldsValue({
      ...config,
      collector:{...config.collector,window_start:config.collector.window_start||(config.collector.no_sleep?'00:00':'07:00'),window_end:config.collector.window_end||'00:00'},
      branding: {
        ...config.branding,
        public_url: config.branding.public_url || window.location.origin,
      },
    });
    onDirtyChange(false);
  }, [config]);
  const field = (
    name: (string | number)[],
    label: string,
    type = "text",
    extra?: string,
  ) => {
    const key = String(name[name.length - 1]);
    const required = [
      "title",
      "interval",
      "pattern",
      "name",
      "timezone",
    ].includes(key);
    const range =
      key === "hour"
        ? { min: 0, max: 23 }
        : key === "max_items"
          ? { min: 1, max: 500 }
          : key === "retry_count"
            ? { min: 0, max: 20 }
            : ["retention_days","delivery_retention_days"].includes(key) ? {min:0,max:3650} : key === "timeout_seconds" ? {min:30,max:1800} : {};
    return (
      <Form.Item
        key={name.join(".")}
        name={name}
        label={label}
        valuePropName={type === "switch" ? "checked" : "value"}
        extra={extra}
        rules={required ? [{ required: true, message: "请填写" + label }] : []}
      >
        {type === "switch" ? (
          <Switch />
        ) : type === "number" ? (
          <InputNumber {...range} precision={0} style={{ width: "100%" }} />
        ) : type === "password" ? (
          <Input.Password autoComplete="new-password" />
        ) : type === "area" ? (
          <Input.TextArea rows={4} />
        ) : (
          <Input />
        )}
      </Form.Item>
    );
  };
  const provider = (key: string, title: string, children: React.ReactNode) => (
    <Card key={key} title={title} size="small" style={{ marginBottom: 16 }} extra={<Form.Item name={['auth',key,'enabled']} valuePropName="checked" style={{margin:0}}><Switch aria-label={`启用${title}`} checkedChildren="开启" unCheckedChildren="关闭"/></Form.Item>}>
      <Form.Item
        noStyle
        shouldUpdate={(a, b) =>
          a.auth?.[key]?.enabled !== b.auth?.[key]?.enabled
        }
      >
        {() =>
          form.getFieldValue(["auth", key, "enabled"]) ? (
            <div className="provider-fields">{children}</div>
          ) : null
        }
      </Form.Item>
    </Card>
  );
  const oauth = (key: string, title: string) =>
    provider(
      key,
      title,
      <>
        {field(["auth", key, "client_id"], "Client ID")}
        {field(["auth", key, "client_secret"], "Client Secret", "password")}
        {key === "oidc" && (
          <>
            {field(["auth", key, "issuer"], "Issuer URL")}
            {field(["auth", key, "scopes"], "附加 Scopes")}
          </>
        )}
        <Form.Item noStyle shouldUpdate>
          {() => (
            <Typography.Text type="secondary">
              回调：
              {form.getFieldValue(["branding", "public_url"]) || "公开访问 URL"}
              /api/oauth/{key}/callback
            </Typography.Text>
          )}
        </Form.Item>
      </>,
    );
  const rules = (kind: "black" | "white") => (
    <>
      <Typography.Paragraph type="secondary">
        {kind === "black"
          ? "命中任一规则即排除。"
          : "启用白名单后，须命中至少一条规则。"}
      </Typography.Paragraph>
      <Alert type="info" showIcon style={{marginBottom:16}} message="正则填写规范" description={<Space direction="vertical" size={6}><Typography.Text>开启正则后使用 Go RE2 语法，直接填写表达式，不加 /…/ 分隔符。默认区分大小写，使用 (?i) 忽略大小写。</Typography.Text><Typography.Text>支持：| 或、.* 任意内容、^ 开头、$ 结尾、[0-9] 数字；不支持前后查找和反向引用。多个字段任一命中即匹配。</Typography.Text><Typography.Text>示例：匹配 MinIO 或 Redis 相关漏洞</Typography.Text><Typography.Text code copyable>{'(?i)(minio|redis).*漏洞'}</Typography.Text><Typography.Text type="secondary">字段选择“标题”，匹配内容填入上例并开启正则。黑名单命中后排除，白名单命中后允许通过；黑名单优先。关闭正则时按不区分大小写的普通关键词匹配。</Typography.Text></Space>}/>
      <Form.List name="rules">
        {(fields, { add, remove }) => (
          <>
            {fields
              .filter(
                (f) => form.getFieldValue(["rules", f.name, "kind"]) === kind,
              )
              .map((f) => (
                <Card
                  key={f.key}
                  size="small"
                  style={{ marginBottom: 16 }}
                  extra={
                    <Button danger type="text" onClick={() => remove(f.name)}>
                      删除
                    </Button>
                  }
                >
                  <Form.Item name={[f.name, "kind"]} hidden>
                    <Input />
                  </Form.Item>
                  {field([f.name, "name"], "名单名称")}
                  {field([f.name, "enabled"], "启用", "switch")}
                  <Form.Item
                    name={[f.name, "fields"]}
                    label="匹配字段"
                    rules={[
                      {
                        required: true,
                        type: "array",
                        min: 1,
                        message: "请选择匹配字段",
                      },
                    ]}
                  >
                    <Select
                      mode="multiple"
                      options={[
                        { value: "title", label: "标题" },
                        { value: "tags", label: "标签" },
                        { value: "description", label: "描述" },
                        { value: "solution", label: "修复方案" },
                      ]}
                    />
                  </Form.Item>
                  {field([f.name, "pattern"], "匹配内容")}
                  {field([f.name, "regex"], "正则表达式", "switch")}
                </Card>
              ))}
            <Button
              onClick={() =>
                add({
                                    enabled: true,
                  kind,
                  fields: ["title"],
                  pattern: "",
                  regex: false,
                })
              }
            >
              添加{kind === "black" ? "黑" : "白"}名单规则
            </Button>
          </>
        )}
      </Form.List>
    </>
  );
  let content: React.ReactNode;
  switch (section) {
    case "collector":
      content = (
        <>
          {field(["collector", "enabled"], "定时采集", "switch")}
          <Form.Item name={["collector", "sources"]} label="漏洞来源">
            <Select
              mode="multiple"
              options={sources.map((value) => ({ value, label: value }))}
            />
          </Form.Item>
          {field(
            ["collector", "interval"],
            "采集间隔",
            "text",
            "例如 30m、1h，至少 1m",
          )}
          {field(["collector", "proxy"], "HTTP / SOCKS5 代理")}
          {field(
            ["collector", "skip_tls_verify"],
            "跳过 TLS 校验（不推荐）",
            "switch",
          )}
          {field(["collector", "enable_cve_filter"], "CVE 跨源去重", "switch")}
          {field(["collector", "no_filter"], "关闭高价值筛选", "switch")}
          {field(
            ["collector", "no_github_search"],
            "禁用 GitHub 搜索",
            "switch",
          )}
          <Form.Item label="每日采集时间" extra={`时区：${config.ai.timezone}。结束早于开始表示跨午夜；起止相同表示全天，仅限制定时采集。`}>
            <Space wrap align="start" size={16}>
              <div><Typography.Text type="secondary">开始时间</Typography.Text><Form.Item name={['collector','window_start']} style={{margin:'6px 0 0'}}><CollectionTime label="开始时间"/></Form.Item></div>
              <div><Typography.Text type="secondary">结束时间</Typography.Text><Form.Item name={['collector','window_end']} style={{margin:'6px 0 0'}}><CollectionTime label="结束时间"/></Form.Item></div>
              <Space style={{marginTop:28}}><Button size="small" onClick={()=>{form.setFieldValue(['collector','window_start'],'00:00');form.setFieldValue(['collector','window_end'],'00:00');onDirtyChange(true)}}>全天</Button><Button size="small" onClick={()=>{form.setFieldValue(['collector','window_start'],'09:00');form.setFieldValue(['collector','window_end'],'18:00');onDirtyChange(true)}}>09:00—18:00</Button></Space>
            </Space>
          </Form.Item>
          {field(["collector", "ai_solution"], "启用AI生成修复方案", "switch", "采集时为通过筛选且无修复方案的漏洞先补充AI建议再推送；AI失败则跳过补充直接推送。可手动生成，将消耗Token。")}
        </>
      );
      break;
    case "black":
    case "white":
      content = rules(section);
      break;
    case "ai_service":
      content=(<>
        <Alert type="info" showIcon message="全局AI服务" description="漏洞AI分析、修复建议及AI报告共用此配置。兼容 /chat/completions 接口，地址填写到 /v1 或服务商指定前缀，不要包含 /chat/completions。" style={{marginBottom:20}}/>
        {field(['ai','enabled'],'启用AI服务','switch')}
        <Form.Item name={['ai','provider']} label="服务商" initialValue="custom"><Select options={[{value:'custom',label:'自定义 / OpenAI兼容接口'},{value:'deepseek',label:'DeepSeek'},{value:'glm',label:'智谱 GLM'},{value:'openai',label:'OpenAI'}]} onChange={provider=>{const presets:Record<string,{base_url:string;model:string}>={deepseek:{base_url:'https://api.deepseek.com/v1',model:'deepseek-chat'},glm:{base_url:'https://open.bigmodel.cn/api/paas/v4',model:'glm-4-flash'},openai:{base_url:'https://api.openai.com/v1',model:'gpt-4o-mini'}};if(presets[provider])form.setFieldsValue({ai:{...form.getFieldValue('ai'),...presets[provider]}});onDirtyChange(true)}}/></Form.Item>
        {field(['ai','base_url'],'API地址','text','可自行修改为国内中转服务或私有部署的兼容接口')}
        {field(['ai','api_key'],'API Key','password')}
        {field(['ai','model'],'模型名称','text','填写账号已开通的模型ID；切换服务商后请同步替换对应密钥')}
        {field(['ai','timeout_seconds'],'单次请求超时（秒）','number','默认300秒；适用于漏洞分析和报告的每次模型请求')}
        {field(['ai','retry_count'],'失败重试次数','number','默认5次；0表示不重试，仅重试失败的模型调用')}
      </>);
      break;
    case "schedule":
      content = (
        <>
          {field(["ai", "daily"], "日报自动生成并推送", "switch")}
          {field(["ai", "weekly"], "周报自动生成并推送", "switch")}
          {field(["ai", "hour"], "开始生成时间（小时）", "number", "按下方时区，0—23点。例如9表示09:00起开始生成，不代表完成时间；服务恢复时可能补执行当天未生成的报告。实际启动受调度检查及运行任务影响。")}
          <Form.Item name={["ai", "weekday"]} label="周报生成星期">
            <Select
              options={[
                "星期日",
                "星期一",
                "星期二",
                "星期三",
                "星期四",
                "星期五",
                "星期六",
              ].map((label, value) => ({ value, label }))}
            />
          </Form.Item>
          {field(["ai", "timezone"], "调度时区")}
          {field(["ai", "max_items"], "每批漏洞数", "number")}
          {field(["ai", "retention_days"], "报告保留天数", "number", "默认7天；0为永久保留，到期删除报告、生成日志和关联投递记录")}
          {field(["ai", "prompt"], "附加分析要求", "area")}
        </>
      );
      break;
    case "notify":
      content = (
        <>
        {field(['delivery_retention_days'],'通知记录保留天数','number','0为永久保留；待投递和仍可重试的失败记录不清理')}
        <Form.List name="notifications">
          {(fields, { add, remove }) => (
            <>
              {fields.map((f) => (
                <Card
                  key={f.key}
                  size="small"
                  title={"通知渠道 " + (f.name + 1)}
                  style={{ marginBottom: 16 }}
                  extra={
                    <Space>
                      <Button
                        loading={testing(form.getFieldValue(["notifications", f.name, "id"]))}
                        onClick={() =>
                          test(form.getFieldValue(["notifications", f.name]))
                        }
                      >
                        测试
                      </Button>
                      <Button danger onClick={() => remove(f.name)}>
                        删除
                      </Button>
                    </Space>
                  }
                >
                  {field([f.name, "name"], "名称")}
                  {field([f.name, "enabled"], "启用", "switch")}
                  <Form.Item name={[f.name, "type"]} label="类型">
                    <Select
                      options={Object.entries(channelNames).map(
                        ([value, label]) => ({ value, label }),
                      )}
                    />
                  </Form.Item>
                  <Form.Item noStyle shouldUpdate>
                    {() => {
                      const type = form.getFieldValue([
                        "notifications",
                        f.name,
                        "type",
                      ]);
                      return (channelFields[type] || []).map((k) =>
                        field(
                          [f.name, "settings", k],
                          k,
                          [
                            "channel",
                            "topic_code",
                            "chat_ids",
                            "domain",
                          ].includes(k)
                            ? "text"
                            : "password",
                        ),
                      );
                    }}
                  </Form.Item>
                </Card>
              ))}
              <Button
                onClick={() =>
                  add({
                                        name: "新通知渠道",
                    enabled: false,
                    type: "dingding",
                    settings: {},
                  })
                }
              >
                添加通知服务
              </Button>
            </>
          )}
        </Form.List>
        </>
      );
      break;
    case "auth":
      content = (
        <>
          {oauth("oidc", "OIDC")}
          {oauth("feishu", "飞书")}
          {oauth("dingtalk", "钉钉")}
          {provider(
            "ldap",
            "LDAP / Active Directory",
            <>
              {field(["auth", "ldap", "url"], "LDAP URL")}
              {field(["auth", "ldap", "bind_dn"], "Bind DN")}
              {field(
                ["auth", "ldap", "bind_password"],
                "服务账户密码",
                "password",
              )}
              {field(["auth", "ldap", "base_dn"], "Base DN")}
              {field(
                ["auth", "ldap", "user_filter"],
                "用户过滤器",
                "text",
                "例如 (uid={username})",
              )}
              {field(["auth", "ldap", "start_tls"], "StartTLS", "switch")}
            </>,
          )}
        </>
      );
      break;
    default:
      content = (
        <>
          {field(
            ["branding", "public_url"],
            "公开访问 URL",
            "text",
            "用于登录回调和报告链接",
          )}
          <Form.Item name={["auth", "report_access"]} label="情报与报告访问" extra="公开访问时，可通过登录页“浏览公开情报”入口进入 /public 查看情报与报告。">
            <Select
              options={[
                { value: "authenticated", label: "仅登录用户" },
                { value: "public", label: "公开访问" },
              ]}
            />
          </Form.Item>
        </>
      );
  }
  return (
    <Card>
      <Form
        form={form}
        layout="vertical"
        initialValues={config}
        onValuesChange={() => onDirtyChange(true)}
        onFinish={() => save(form.getFieldsValue(true))}
      >
        <div className="settings-fields" key={section}>
          {content}
        </div>
        <div className="savebar">
          <Button type="primary" htmlType="submit" loading={busy}>
            保存配置
          </Button>
        </div>
      </Form>
    </Card>
  );
}

export function SettingsTabs({
  section,
  onChange,
}: {
  section: string;
  onChange: (key: string) => void;
}) {
  return (
    <Tabs
      activeKey={section}
      onChange={onChange}
      items={[
        { key: "branding", label: "访问设置" },
        { key: "ai_service", label: "AI设置" },
      ]}
    />
  );
}
