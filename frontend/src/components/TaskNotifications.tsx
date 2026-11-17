import {useState} from 'react';
import {Badge,Button,Drawer,Empty,List,Space,Tag,Typography} from 'antd';
import {BellOutlined} from '@ant-design/icons';
import type {Obj} from '../lib/api';
export function TaskNotifications({reports,jobs,health,onReport}:{reports:Obj[];jobs:Obj[];health:Obj[];onReport:(r:Obj)=>void}){
 const [open,setOpen]=useState(false);
 const items=[...reports.map(r=>({id:r.id,title:r.title,status:r.status,error:r.error,time:r.created_at,report:r})),...jobs.map(j=>({id:j.id,title:j.vulnerability_id?'手动推送 · '+j.title:j.baseline?'首次漏洞采集 · 请访问漏洞列表查看':'漏洞采集任务',status:j.status,error:j.error,time:j.finished_at||j.created_at,report:null})),...health.map(h=>({id:'source:'+h.source,title:'源状态检查 · '+h.source,status:h.status,error:h.error,time:h.checked_at,report:null}))].sort((a,b)=>{const run=(s:string)=>['running','queued','generating','checking'].includes(s)?1:0;return Date.parse(b.time)-Date.parse(a.time)}).slice(0,20);
 const active=items.filter(i=>['running','queued','generating','checking'].includes(i.status)).length;
 const labels:Record<string,string>={running:'进行中',queued:'排队中',generating:'生成中',checking:'检查中',ready:'已完成',healthy:'正常',empty:'空结果',failed:'失败',cancelled:'已取消'};
 return <><Badge count={active} size="small"><Button shape="circle" icon={<BellOutlined/>} aria-label="任务通知" onClick={()=>setOpen(true)}/></Badge><Drawer title="通知与任务" open={open} onClose={()=>setOpen(false)} width={460}><List dataSource={items} locale={{emptyText:<Empty description="暂无消息"/>}} renderItem={item=><List.Item><Space direction="vertical" style={{width:'100%'}}><Space><Tag color={['failed'].includes(item.status)?'red':['running','queued','generating','checking'].includes(item.status)?'processing':'default'}>{labels[item.status]||item.status}</Tag>{item.report?<a onClick={()=>{onReport(item.report!);setOpen(false)}}>{item.title}</a>:<Typography.Text>{item.title}</Typography.Text>}</Space>{item.error&&<Typography.Text type="danger">{item.error}</Typography.Text>}<Typography.Text type="secondary">{new Date(item.time).toLocaleString()}</Typography.Text></Space></List.Item>}/></Drawer></>;
}
