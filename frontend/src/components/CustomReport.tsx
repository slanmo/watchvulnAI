import {useState} from 'react';
import {Button,DatePicker,Form,Modal,Typography} from 'antd';
export function CustomReport({disabled,generate}:{disabled:boolean;generate:(start:string,end:string)=>Promise<void>}){
 const [open,setOpen]=useState(false),[loading,setLoading]=useState(false);const [form]=Form.useForm();
 return <><Button disabled={disabled} onClick={()=>setOpen(true)}>自定义周期</Button><Modal open={open} title="生成周期分析报告" centered width={480} onCancel={()=>setOpen(false)} okText="开始分析" cancelText="取消" confirmLoading={loading} onOk={()=>form.submit()}><Typography.Paragraph type="secondary">日期按东八区解释，包含结束日期；分析周期内入库且筛选通过的记录，将消耗Token。</Typography.Paragraph><Form form={form} layout="vertical" onFinish={async v=>{setLoading(true);try{await generate(v.period[0].format('YYYY-MM-DD'),v.period[1].format('YYYY-MM-DD'));setOpen(false)}finally{setLoading(false)}}}><Form.Item name="period" label="统计周期" rules={[{required:true,message:'请选择开始和结束日期'}]}><DatePicker.RangePicker style={{width:'100%'}} format="YYYY-MM-DD"/></Form.Item></Form></Modal></>;
}
