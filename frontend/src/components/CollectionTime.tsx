import {Select,Space,Typography} from 'antd';

type Props={value?:string;onChange?:(value:string)=>void;label:string};
export function CollectionTime({value='00:00',onChange,label}:Props){
 const [hour='00',minute='00']=value.split(':');
 const options=(count:number)=>Array.from({length:count},(_,i)=>{const value=String(i).padStart(2,'0');return {value,label:value}});
 return <Space size={6}>
  <Select aria-label={label+'小时'} value={hour} onChange={h=>onChange?.(h+':'+minute)} options={options(24)} style={{width:80}}/>
  <Typography.Text>:</Typography.Text>
  <Select aria-label={label+'分钟'} value={minute} onChange={m=>onChange?.(hour+':'+m)} options={options(60)} style={{width:80}} showSearch/>
 </Space>;
}
