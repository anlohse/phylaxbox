const logit = function() {
    console.log('I did it!');
}

const chenge = function () {
    let div = document.body.querySelector('div');
    div.innerHTML += "<p>App carregado!</p>";
    logit();
}

export {chenge};
