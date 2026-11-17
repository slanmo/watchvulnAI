import {useEffect,useState} from 'react';
import {Alert,Card,Input,Table,Tag,Typography} from 'antd';
import {api,type Obj} from '../lib/api';
export function PublicVulnerabilities(){
 const [rows,setRows]=useState<Obj[]>([]),[search,setSearch]=useState(''),[error,setError]=useState('');
 useEffect(()=>{let active=true;api('/vulnerabilities').then(v=>{if(active)setRows(v)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[]);
 return <Card title="公开漏洞情报" style={{marginTop:24}}>{error&&<Alert type="error" message={error}/>}<Input.Search placeholder="搜索标题或CVE" allowClear onChange={e=>setSearch(e.target.value)} style={{marginBottom:16}}/><Table size="small" rowKey="id" dataSource={rows.filter(v=>(v.title+' '+v.cve).toLowerCase().includes(search.toLowerCase()))} columns={[{title:'标题',dataIndex:'title',onCell:()=>({style:{width:'100%'}}),render:(v,r)=><Typography.Link className="vulnerability-title" title={v} href={'/vulnerabilities/'+r.id} target="_blank">{v}</Typography.Link>},{title:'来源',dataIndex:'source',onCell:()=>({style:{whiteSpace:'nowrap'}})},{title:'筛选',dataIndex:'selected',onCell:()=>({style:{whiteSpace:'nowrap'}}),render:v=><Tag color={v?'green':'default'}>{v?'通过':'排除'}</Tag>}]} pagination={{defaultPageSize:10,showSizeChanger:true,pageSizeOptions:[5,10,20,50,100],showTotal:n=>`共 ${n} 条`}}/></Card>
}
