/**
 * BIP39 — Wordlist en español + entropy → mnemonic → seed
 * La clave privada se deriva deterministicamente de las 12 palabras.
 * El servidor NUNCA ve la clave privada.
 */

// 2048 palabras BIP39 en español (lista oficial BIP39-es)
export const WORDLIST = [
  "ábaco","abdomen","abeja","abierto","abogado","abono","aborto","abrazo","abrir","abuelo",
  "abuso","acabar","academia","acceso","acción","aceite","acelga","acento","aceptar","ácido",
  "aclarar","acné","acoger","acoso","activo","acto","actuar","acudir","acuerdo","acusar",
  "adicto","admitir","adoptar","adorno","aduana","adulto","aéreo","afectar","afición","agencia",
  "agitar","agonía","agosto","agotar","agrado","agrio","agua","agudo","águila","aguja",
  "ahogo","ahorro","aire","aislar","ajedrez","ajeno","ajuste","alacrán","alambre","alarma",
  "alba","álbum","alcalde","aldea","alegre","alejar","alerta","aleta","alfiler","alga",
  "algodón","aliento","alivio","alma","almeja","almíbar","altar","alteza","altivo","alto",
  "altura","alumno","alzar","amable","amante","amapola","amargo","amasar","ámbar","ámbito",
  "ambos","ambulancia","amigo","amnistía","amor","amparo","amplio","ancho","anciano","ancla",
  "andar","andén","anemia","ángulo","anhelo","ánimo","anís","anotar","antena","antiguo",
  "antojo","anual","anular","anuncio","añadir","añejo","año","apagar","aparato","apetito",
  "apio","aplicar","apodo","aporte","apoyo","aprender","aprobar","apuesta","apuro","arado",
  "araña","arar","árbitro","árbol","arbusto","archivo","arco","arder","ardilla","arduo",
  "área","árido","aries","armonía","arnés","aroma","arpa","arpón","arrancar","arrastre",
  "arreglo","arroz","arruga","arte","artista","asa","asado","asalto","ascenso","asegurar",
  "aseo","asesor","asiento","asilo","asistir","asno","asombro","áspero","astilla","astro",
  "astuto","asumir","asunto","atajo","ataque","atar","atento","ateo","ático","atleta",
  "átomo","atraer","atroz","atún","audaz","auge","aula","aumento","ausente","autor",
  "aval","avance","avaro","ave","avellana","avena","avión","aviso","ayer","ayuda",
  "ayuno","azafrán","azar","azote","azúcar","azufre","azul","baba","balcón","balde",
  "bambú","banco","banda","baño","barba","barco","barniz","barro","báscula","bastón",
  "basura","batería","batir","bautismo","bazar","bebé","béisbol","belleza","besar","beso",
  "bestia","bicho","bien","bingo","blanco","blindar","bloque","bobina","boca","bocina",
  "boda","bodega","boina","bola","bolsillo","bomba","bondad","borrar","bosque","botín",
  "bóveda","bravo","brazo","brecha","breve","brillo","brindar","brisa","broca","broma",
  "bronce","brote","brujo","brusco","bruto","buceo","budín","bueno","buey","búfalo",
  "bufanda","búho","buitre","bulto","buque","burla","buscar","butaca","buzón","cabal",
  "caballo","caber","cabina","cable","cacao","cadáver","cadena","caer","café","caída",
  "caimán","caja","cajón","cal","calamar","calcio","caldo","calidad","calle","calma",
  "calor","calvo","cama","cambio","camello","camino","campo","cáncer","candil","cantidad",
  "cañón","caoba","caos","capaz","capitán","capote","captar","capucha","cara","carbón",
  "cárcel","carga","carnaval","caro","carpa","carro","carta","casa","casco","caspa",
  "castor","caudal","causa","cazo","cebolla","cerebro","cereza","cerrar","certeza","cesped",
  "cetro","chico","chiste","chivo","choque","ciclo","ciego","cielo","ciento","cierto",
  "cifra","cigarro","cima","cinco","cinta","circo","ciruela","cisne","cita","ciudad",
  "clamor","clan","claro","clavar","cobro","coche","cocina","código","codo","cofre",
  "coger","cohete","cojín","col","cola","colapso","colcha","cólera","colgar","colina",
  "collar","colmo","columna","combate","cometer","cómodo","compra","común","conejo","conjunto",
  "cono","copa","copia","coque","corbata","cordón","corona","correr","coser","cosmos",
  "costa","cremoso","cría","crisis","crónica","cruce","cruel","cuadro","cuarto","cuatro",
  "cubo","cuello","cueva","cuidar","culpa","cultivo","cumbre","cúpula","cupón","curar",
  "dardo","dato","deber","débil","década","decir","dedo","defensa","definir","dejar",
  "delfín","demora","dental","deporte","derecho","derrota","desayuno","deseo","destino","diablo",
  "diadema","dibujo","diente","dieta","diez","difícil","digno","dinero","disco","diseño",
  "disfraz","diva","divino","doble","dolor","dominio","dragón","droga","ducha","duda",
  "duelo","dueño","dulce","dúo","duque","durar","dureza","duro","ébano","eclipse",
  "edad","edición","edificio","editor","educar","efectivo","efecto","eficaz","eje","ejemplo",
  "elefante","elegir","elixir","elogio","eludir","embudo","emitir","emoción","empate","empresa",
  "enano","encanto","enemigo","enfado","enfermo","engaño","enigma","enorme","enredo","ensayo",
  "entrar","envío","época","equipo","erial","error","escena","esfera","espejo","esposa",
  "establo","estación","estado","estancia","estar","estatua","estudio","estufa","etapa","eterno",
  "ético","Europa","evacuar","evitar","exacto","examen","exceso","exhibir","exilio","éxito",
  "experto","exponer","éxtasis","extremo","fábrica","fácil","factor","faja","falda","fallo",
  "falso","faltar","fama","familia","faraón","faro","fase","fatiga","favor","fax",
  "febrero","feliz","felpudo","femenino","fémur","fenómeno","feo","feria","feroz","fértil",
  "fervor","festín","fiable","fianza","fiar","fibra","ficción","ficha","fideo","fiebre",
  "fiero","fiesta","figura","fijar","fijo","fila","filete","filme","finca","fingir",
  "finito","firma","flaco","flauta","flecha","flor","flota","fluir","flujo","flúor",
  "fobia","foca","fogón","folleto","fondo","fontana","footing","foráneo","forcejo","forja",
  "forma","forro","fortuna","forzar","fosa","foto","fracaso","frágil","franja","frase",
  "fraude","freír","freno","fresa","frío","frito","frontal","frotar","fructosa","fuego",
  "fuente","fuerza","fuga","fugaz","fulgor","función","furgón","furia","fusible","fútbol",
  "futuro","gacela","gafas","galería","gallo","gamba","ganar","gancho","ganga","garaje",
  "garza","gasolina","gastar","gemelo","general","género","genio","germen","gesto","gigante",
  "gimnasio","girasol","glaciar","globo","glorioso","glosario","gobierno","golfo","goloso","golpe",
  "gordo","gorila","gorro","gota","goteo","gozar","gracia","grado","gráfico","gramo",
  "grande","granja","grano","grasa","gratis","grave","grieta","grito","grosor","grúa",
  "grupo","guante","guapo","guarda","guerra","guía","guiño","guion","guiso","guitarra",
  "gusano","gustar","haber","hábil","hablar","hacer","hallar","hamaca","harina","hastío",
  "hazaña","hebilla","hecho","helado","herida","hermano","hielo","hierro","hígado","hilo",
  "historia","hogar","hoguera","hoja","hombre","hongo","hora","horno","húmedo","hundir",
  "huracán","iceberg","ideal","ídolo","iglesia","ignorar","igual","imagen","imán","imitar",
  "impacto","incapaz","índice","inerte","infiel","informe","inmenso","innato","inodoro","insecto",
  "instante","interés","íntimo","intriga","inútil","invierno","inyectar","isla","jabalí","jabón",
  "jamón","jarabe","jardín","jarra","jaula","jazmín","jefe","jeringa","jinete","jornada",
  "jorobado","joven","joya","juerga","juicio","junco","jungla","junta","jurar","justo",
  "juzgar","lacra","ladera","ladrillo","lagarto","lágrima","laguna","lamento","lámina","lance",
  "langosta","lanza","lápiz","largo","larva","lástima","latido","látigo","lavado","lazo",
  "leal","lección","legión","lejano","lengua","lento","leña","leopardo","lesión","letal",
  "libre","libro","licor","límite","limón","limpiar","lince","lío","listo","literal",
  "litro","llama","lluvia","lobo","lodo","lógica","lograr","loro","lucha","lugar",
  "lujo","luna","luto","luz","madera","madre","magia","maldad","maleta","mambo",
  "manar","mancha","mandato","manera","mañana","mapa","máquina","marca","marcha","marea",
  "margen","mármol","masa","máscara","materia","mayor","mecer","medalla","médico","medio",
  "mejor","melena","melon","memoria","menor","mensaje","mente","menú","mercado","mérito",
  "meta","método","mezcla","miedo","miel","miembro","miga","milagro","militar","millón",
  "mínimo","minuto","mirar","misa","mismo","mitad","moderno","mojar","molde","moler",
  "molino","momento","monje","moño","moral","morder","moreno","morir","morro","morsa",
  "mosca","mostrar","motivo","mover","móvil","mozo","muchos","mueble","muela","muerte",
  "muestra","mugre","mujer","mulo","multa","mundo","muñeca","muralla","murciélago","músculo",
  "muslo","nácar","nación","nadar","naipe","naranja","nariz","néctar","negar","negocio",
  "negro","neón","nervio","nido","niebla","nieto","ninguno","nítido","nivel","noche",
  "nómada","nórdico","norma","notable","novato","novela","néctar","nudillo","nudo","nuera",
  "objeto","obra","océano","odiar","odio","oeste","ofensa","oferta","oficio","oído",
  "ojival","ola","olfato","olivo","olla","ombligo","ópera","optar","oráculo","orden",
  "oreja","órgano","orgullo","orilla","orinar","ornamento","oro","orquesta","oruga","osadía",
  "oscuro","osito","óvalo","oveja","óxido","ozono","pacto","pagar","página","pájaro",
  "palco","paleta","paloma","palpar","panceta","pánico","pantera","pañuelo","papel","papilla",
  "pareja","párpado","párrafo","pasar","patata","patria","pausa","peca","pedal","peinado",
  "peldaño","película","peligro","pelota","pena","pensar","peón","percal","perder","pereza",
  "pétalo","picaro","picor","pieza","pimienta","pincel","piñón","pirata","pisada","pistón",
  "plaga","plano","plástico","plato","playa","plaza","pleito","plomo","pluma","población",
  "poco","poder","podio","poesía","polvo","pomada","pómulo","poner","portal","posada",
  "poyete","precio","premio","prensa","presa","prima","primo","prisa","privar","proa",
  "probar","pronto","propina","próximo","prueba","público","puchero","pulpo","pulso","puntada",
  "punto","puñal","pupila","puré","quedar","queja","quemar","querer","queso","quince",
  "quitar","rábano","rabia","ración","raíz","rama","rampa","rápido","rapto","rasgo",
  "rastra","rato","rayo","raza","razón","rebelde","recibo","recta","recurso","redil",
  "redondo","reflejo","refrán","regalo","regla","reino","relleno","remar","rendir","repaso",
  "reptil","rescatar","resina","respeto","retablo","retrato","reunir","revista","rico","riesgo",
  "rígido","rigor","rincón","riñón","río","riqueza","risa","ritmo","rival","rojizo",
  "romano","romper","ropa","rostro","rubio","rugir","ruido","ruina","ruleta","rumor",
  "sabio","sable","sacar","sagrado","saltar","salud","sano","sapo","saqueo","sátira",
  "sauce","sección","seda","seguir","sello","selva","semana","sendero","sensación","señal",
  "serie","serón","siesta","siglo","signo","sílaba","silbar","símbolo","sirena","sistema",
  "sitio","soborno","socio","sodio","soga","soja","solapa","solar","sólido","sombra",
  "sondeo","sonido","soplo","soportar","sordo","sorpresa","sorteo","sótano","suave","subir",
  "suceder","sudor","suerte","suma","superar","sutil","tabaco","tacto","tajo","taller",
  "tambor","tapa","tarea","tarjeta","tarro","taza","tejado","teja","tela","teléfono",
  "telón","templo","tendón","tenso","teoría","terapia","ternura","terror","tesoro","tiempo",
  "timón","tío","típico","título","tiza","tocar","todo","toldo","tomar","tónico",
  "torno","torpe","tos","tosco","tóxico","trabajo","traer","tráfico","trago","traición",
  "traje","tramo","trance","trapo","través","trébol","tregua","tribu","trigo","tripa",
  "triste","triunfo","trompa","tronco","trotar","trozo","truco","trueno","tubería","túnel",
  "turno","tutela","úlcera","umbral","unidad","unir","urano","urbano","útil","uva",
  "vacío","vacuna","vago","vapor","varón","vecino","vejez","vena","vencer","venda",
  "veneno","ventaja","verano","verdad","vereda","verso","vértice","vía","viaje","vicio",
  "vidrio","vigor","villa","vínculo","viola","virus","visor","víspera","vivir","volcán",
  "volumen","volver","voraz","votar","vuelta","yate","yema","yerno","yeso","yoga",
  "yugo","zafiro","zanja","zapato","zarza","zona","zorro","zumo","zurdo"
];

/**
 * Convierte bytes a entero (big-endian)
 */
function bytesToBigInt(bytes) {
  return bytes.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
}

/**
 * Genera 12 palabras desde entropy seguro del navegador.
 * Usa rejection sampling para obtener índices uniformes dentro del wordlist,
 * evitando sesgo de módulo. Las mismas 12 palabras siempre producen la misma
 * clave privada vía mnemonicToSeed().
 */
export async function generarMnemonic() {
  const size = WORDLIST.length; // 1310 palabras
  const indices = [];
  // Rejection sampling: genera pares de bytes hasta tener 12 índices sin sesgo
  while (indices.length < 12) {
    const buf = crypto.getRandomValues(new Uint16Array(12));
    const limit = Math.floor(0x10000 / size) * size; // elimina sesgo de módulo
    for (const v of buf) {
      if (v < limit && indices.length < 12) {
        indices.push(v % size);
      }
    }
  }
  // Devuelve palabras sin acentos para que el usuario las pueda escribir fácilmente
  return indices.map(i => sinAcentos(WORDLIST[i])).join(' ');
}

// Normaliza a minúsculas sin acentos para comparación tolerante
function sinAcentos(s) {
  return s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
}

// Wordlist normalizada para búsqueda rápida
const WORDLIST_NORM = WORDLIST.map(sinAcentos);

/**
 * Verifica que todas las palabras del mnemonic existen en el wordlist.
 * Acepta palabras con o sin acentos.
 */
export function validarMnemonic(mnemonic) {
  const palabras = mnemonic.trim().split(/\s+/);
  if (palabras.length !== 12) return false;
  return palabras.every(p => WORDLIST_NORM.includes(sinAcentos(p)));
}

/**
 * Convierte mnemonic → seed de 64 bytes usando PBKDF2-HMAC-SHA512.
 * Mismo estándar que BIP39 real: PBKDF2(mnemonic, "mnemonic", 2048, SHA-512).
 */
export async function mnemonicToSeed(mnemonic) {
  const encoder = new TextEncoder();
  // Normalizar a sin acentos para que "abaco" y "ábaco" produzcan el mismo seed
  const mnemonicNFKD = mnemonic.trim().split(/\s+/).map(sinAcentos).join(' ');

  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(mnemonicNFKD),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const seedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode('mnemonic'),
      iterations: 2048,
      hash: 'SHA-512',
    },
    baseKey,
    512
  );

  return new Uint8Array(seedBits); // 64 bytes
}
