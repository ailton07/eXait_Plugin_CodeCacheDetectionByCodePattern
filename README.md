eXait Plugin for Detect Pin by Code Cache Detection (Code Pattern)
===================

Binário criado para detectar quando está sendo executado/analisado pelo PIN.


Requirements
-------------
> - Visual Studio 2010
> -  Pin funcional de acordo com a documentação [Intel] [1].
> -  [x64dbg] [9] para análise .

----------

What's eXait
-------------
https://www.coresecurity.com/corelabs-research/open-source-tools/exait

----------


Executing
-------------

O projeto inclui a dll já buildada.
Basta copiar o arquivo 
> eXait_CodeCacheDetectionByCode.dll

Para 
> eXait v1.0\bin\plugins\

Para testar sem o Pin, basta dar dois cliques em:
> eXait v1.0\bin\exait_gui.exe

> ![PIN_NOT_DETECTED](https://i.imgur.com/RuR269p.png)

Analisando com x32dbg
>Pelo ![x32dbg](https://i.imgur.com/5neo7lU.png) :

Para executar com o Pin:
>pin.exe -- eXait v1.0\bin\exait_gui.exe

>![PIN_DETECTED](https://i.imgur.com/hdmQJvg.png) 

Analisando com x32dbg
>Pelo ![x32dbg](https://i.imgur.com/66ZVRXs.png) :

----------     

Funcionamento
-------------------
O funcionamento do binário para a detecção do PIN é baseado no trabalho apresentado no Black Hat 2016 | Break Out of The Truman Show: Active Detection and Escape of Dynamic Binary Instrumentation, trabalho de Ke Sun, Xiaoning Li e Ya Ou . A apresentação está disponível neste [link](https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf).
ME

  [1]: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool
  [2]: http://daringfireball.net/projects/markdown/syntax "Markdown"
  [3]: https://github.com/jmcmanus/pagedown-extra "Pagedown Extra"
  [4]: http://meta.math.stackexchange.com/questions/5020/mathjax-basic-tutorial-and-quick-reference
  [5]: https://code.google.com/p/google-code-prettify/
  [6]: http://highlightjs.org/
  [7]: http://bramp.github.io/js-sequence-diagrams/
  [8]: http://adrai.github.io/flowchart.js/
  [9]: https://github.com/x64dbg/x64dbg
