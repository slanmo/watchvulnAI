import {Card,Collapse,Typography,Space,Tag} from 'antd';
import type {Obj} from '../lib/api';
export function ReportEvents({events}:{events:Obj[]}){
 const blocks: {id:string;events:Obj[]}[]=[];
 for(const event of events){const id=event.call_id||event.id;let block=blocks.find(b=>b.id===id);if(!block){block={id,events:[]};blocks.push(block)}block.events.push(event)}
 if(!blocks.length)return <Typography.Text type="secondary">等待任务开始…</Typography.Text>;
 let call=0;
 return <Space direction="vertical" style={{width:'100%'}}>{blocks.map(block=>{
 const isCall=!!block.events[0].call_id;
 const title=isCall?`模型调用 ${++call}`:({progress:'批次进度',retry:'失败与重试',error:'任务结果'} as Record<string,string>)[block.events[0].kind]||'交互记录';
 return <Card key={block.id} size="small" title={<Space>{title}{isCall&&<Tag color="blue">调用</Tag>}</Space>}>
 {block.events.filter(e=>e.kind!=='prompt').map(e=><pre key={e.id} className="preserve" style={{maxHeight:450,overflow:'auto',margin:0}}>{e.content}</pre>)}
 {block.events.some(e=>e.kind==='prompt')&&<Collapse ghost items={block.events.filter(e=>e.kind==='prompt').map(e=>({key:e.id,label:'Prompt 与输入',children:<pre className="preserve" style={{maxHeight:350,overflow:'auto',margin:0}}>{e.content}</pre>}))}/>}
 </Card>})}</Space>
}
