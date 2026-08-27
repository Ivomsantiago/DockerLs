package scan

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ErrOutputTooLarge é o teto do que um scanner pode escrever num stream.
// Saída sem limite não é medição: o documento nunca foi lido inteiro,
// então não há o que interpretar nem o que concluir.
var ErrOutputTooLarge = errors.New("scanner output exceeded the size limit")

// terminateGrace é quanto um scanner sinalizado ganha para sair sozinho
// antes do SIGKILL. Trivy e Grype descarregam e saem na hora; isto só
// limita o caso patológico de um processo ignorando SIGTERM.
const terminateGrace = 5 * time.Second

// runResult é o que uma execução produziu.
type runResult struct {
	exitCode int
	stdout   []byte
	stderr   []byte
	timedOut bool
	err      error
}

// boundedWriter acumula até `limit` bytes e descarta o resto.
//
// Descartar em vez de devolver erro é deliberado: um erro de escrita faz o
// `os/exec` parar de copiar, e um scanner que continue escrevendo bloqueia
// num pipe cheio e nunca sai -- trocando um teto de memória por um
// processo pendurado. Descartando, a memória fica limitada, o filho
// termina normalmente, e `exceeded` diz ao chamador que o documento está
// incompleto e não deve ser interpretado.
type boundedWriter struct {
	limit    int64
	buf      []byte
	exceeded bool
	// onExceed é chamado uma vez, no instante em que o teto estoura, para
	// que o chamador possa encerrar o processo em vez de esperá-lo
	// terminar de escrever o que já não interessa.
	onExceed func()
	once     sync.Once
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	room := w.limit - int64(len(w.buf))
	if room > 0 {
		take := int64(len(p))
		if take > room {
			take = room
		}
		w.buf = append(w.buf, p[:take]...)
	}
	if int64(len(w.buf)) >= w.limit && int64(len(p)) > room {
		w.exceeded = true
		if w.onExceed != nil {
			w.once.Do(w.onExceed)
		}
	}
	// Sempre `len(p), nil`: ver o comentário do tipo.
	return len(p), nil
}

// runCapture executa `argv` e garante que o processo é encerrado e
// colhido por todo caminho de saída.
//
// Os streams são ligados a writers em vez de `StdoutPipe`/`StderrPipe`
// porque `Cmd.Wait` fecha os pipes assim que vê o processo sair -- ler
// deles numa goroutine paralela ao `Wait` é uma corrida, e o lado perdedor
// entrega saída truncada ou vazia. Com `cmd.Stdout` atribuído, é o próprio
// `Wait` que espera a cópia terminar antes de retornar.
//
// Duas coisas que a versão Python não conseguia fazer e esta faz:
//
//   - o filho nasce no próprio grupo de processos (Setpgid), e o timeout
//     mata o *grupo*. O Trivy dispara subprocessos para pull e extração;
//     matar só o líder deixava netos vivos, ainda segurando o lock BoltDB
//     que o pool de cache existe para não disputar;
//   - o teto de saída encerra o scan em vez de continuar acumulando.
func runCapture(parent context.Context, argv []string, timeout time.Duration, maxBytes int64) runResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv, nunca shell
	// Sem shell em canto nenhum: `exec.Command` recebe argv já separado,
	// então uma referência de imagem não tem como virar comando.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	kill := func() { killGroup(cmd) }
	outW := &boundedWriter{limit: maxBytes, onExceed: kill}
	errW := &boundedWriter{limit: maxBytes, onExceed: kill}
	cmd.Stdout = outW
	cmd.Stderr = errW

	if err := cmd.Start(); err != nil {
		return runResult{err: err}
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var (
		waitErr  error
		timedOut bool
	)
	select {
	case waitErr = <-waitCh:
	case <-ctx.Done():
		timedOut = true
		killGroup(cmd)
		// Colher mesmo assim: sem isto o processo vira zumbi e o run
		// seguinte disputa o mesmo lock com um fantasma.
		select {
		case waitErr = <-waitCh:
		case <-time.After(terminateGrace):
			waitErr = ctx.Err()
		}
	}

	// Aqui `Wait` já retornou, então as goroutines de cópia do `os/exec`
	// terminaram e os buffers podem ser lidos sem corrida.
	if outW.exceeded || errW.exceeded {
		return runResult{err: ErrOutputTooLarge, stderr: errW.buf}
	}

	code := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code = exitErr.ExitCode()
		} else if !timedOut {
			return runResult{err: waitErr, stdout: outW.buf, stderr: errW.buf}
		}
	}

	return runResult{
		exitCode: code,
		stdout:   outW.buf,
		stderr:   errW.buf,
		timedOut: timedOut,
	}
}

// killGroup derruba o processo e tudo que ele gerou.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		return
	}
	// SIGTERM no grupo, depois SIGKILL: o Trivy descarrega o cache ao
	// receber o primeiro, e matar direto deixaria a base pela metade.
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	time.AfterFunc(terminateGrace, func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
}
