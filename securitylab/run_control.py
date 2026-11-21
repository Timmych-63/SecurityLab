"""Cooperative stop and bounded persisted stage events, owned by one dashboard run."""
import json
import threading
import time
from .storage import atomic_text

class RunControl:
    def __init__(self, path):
        self.path=path
        self.stop=threading.Event()
        self.lock=threading.RLock()
        self.started=time.monotonic()
        self.data={'events':[], 'stages':[], 'cancelRequested':False}

    def emit(self, stage, state, text):
        with self.lock:
            t=round(time.monotonic()-self.started,3)
            self.data['events'].append(dict(t=t,source='securitylab',text=text))
            self.data['events']=self.data['events'][-200:]
            row=next((r for r in self.data['stages'] if r['id']==stage),None)
            if row is None:
                labels={'red':'Red · анализ','blue_1':'Blue · предложение 1','blue_2':'Blue · предложение 2',
                        'baseline':'Исходный снимок','candidate':'Кандидат 1','candidate_retry':'Кандидат 2',
                        'recheck':'Повторная проверка','commit':'Изолированный коммит','cancellation':'Остановка','result':'Результат',
                        'prepare':'Подготовка','confirm':'Независимое подтверждение'}
                row=dict(id=stage,label=labels.get(stage,stage),role=stage,state=state,startedAt=t)
                self.data['stages'].append(row)
            row.update(state=state,detail=text)
            if state in ('done','failed','skipped'):row['finishedAt']=t
            atomic_text(self.path,json.dumps(self.data,ensure_ascii=False,indent=2))

    def cancel(self):
        with self.lock:
            self.stop.set()
            self.data['cancelRequested']=True
            self.emit('cancellation','running','Отмена запрошена; ожидаем остановки и очистки контейнеров.')

    def finish(self,status,reason=None):
        with self.lock:
            for row in self.data['stages']:
                if row['state'] in ('running','wait_model'):
                    row.update(state='skipped' if status=='STOPPED' else 'failed',finishedAt=round(time.monotonic()-self.started,3))
            detail='Результат: '+status
            if reason: detail+=' · Причина: '+str(reason)[:2000]
            self.emit('result','done' if status in ('PASS','STOPPED') else 'failed', detail)
